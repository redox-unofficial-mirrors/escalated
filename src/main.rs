// TODO: Move file descriptor number allocation to relibc, eliminating SYS_WRITE unsafety (for
// SKMSG_FOBTAINFD).
//
//#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;

use redox_scheme::scheme::SchemeSync;
use redox_scheme::{
    CallerCtx, OpenResult, RequestKind, Response, SendFdRequest, SignalBehavior, Socket,
};
use syscall::error::*;
use syscall::flag::*;

use redox_rt::proc::FdGuard;
use syscall::schemev2::NewFdFlags;

struct MemoryFd(FdGuard);
struct ExecFd(FdGuard);
struct ContextFd(FdGuard);

struct Scheme {
    next_fd: usize,
    handles: HashMap<usize, Handle>,
    memory: MemoryFd,
}
enum Handle {
    AwaitingContextFd {
        pid: usize,
    },
    AwaitingExecFd {
        ctx: ContextFd,
    },
    AwaitingPath {
        exec: ExecFd,
        ctx: ContextFd,
    },
    AwaitingArgs {
        exec: ExecFd,
        ctx: ContextFd,
        path: Box<str>,
    },
    AwaitingEnvs {
        exec: ExecFd,
        ctx: ContextFd,
        path: Box<str>,
        args: Box<[u8]>,
    },
    AwaitingCwd {
        exec: ExecFd,
        ctx: ContextFd,
        path: Box<str>,
        args: Box<[u8]>,
        envs: Box<[u8]>,
    },
    AwaitingDefaultScheme {
        exec: ExecFd,
        ctx: ContextFd,
        path: Box<str>,
        args: Box<[u8]>,
        envs: Box<[u8]>,
        cwd: Box<str>,
    },
    // TODO: Make cwd an fd too?
    Finished {
        exec: ExecFd,
        ctx: ContextFd,
        path: Box<str>,
        args: Box<[u8]>,
        envs: Box<[u8]>,
        cwd: Box<str>,
        default_scheme: Box<str>,
    },
    Placeholder,
}

impl SchemeSync for Scheme {
    fn open(&mut self, path: &str, _flags: usize, ctx: &CallerCtx) -> Result<OpenResult> {
        // Path must be empty
        if path.trim_start_matches('/') != "" {
            return Err(Error::new(ENOENT));
        }
        let fd = self.next_fd;
        self.next_fd = self.next_fd.checked_add(1).ok_or(Error::new(EMFILE))?;
        self.handles
            .insert(fd, Handle::AwaitingContextFd { pid: ctx.pid });

        Ok(OpenResult::ThisScheme {
            number: fd,
            flags: NewFdFlags::empty(),
        })
    }
    fn call(&mut self, id: usize, _payload: &mut [u8], _metadata: &[u64]) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let Handle::Finished {
            exec,
            ctx,
            path,
            args,
            envs,
            cwd,
            default_scheme,
        } = std::mem::replace(handle, Handle::Placeholder)
        else {
            return Err(Error::new(EBADF));
        };
        execute(
            &self.memory,
            ctx,
            exec,
            &path,
            &args,
            &envs,
            &cwd,
            &default_scheme,
        )?;

        Ok(0)
    }
    fn write(
        &mut self,
        id: usize,
        buf: &[u8],
        _off: u64,
        _flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let validate_utf8 = |buf| std::str::from_utf8(buf).map_err(|_| Error::new(EINVAL));

        match std::mem::replace(handle, Handle::Placeholder) {
            old @ (Handle::AwaitingExecFd { .. } | Handle::AwaitingContextFd { .. }) => {
                *handle = old;
                return Err(Error::new(EINVAL));
            }
            Handle::AwaitingPath { exec, ctx } => {
                *handle = Handle::AwaitingArgs {
                    exec,
                    ctx,
                    path: validate_utf8(buf)?.into(),
                }
            }
            Handle::AwaitingArgs { exec, ctx, path } => {
                *handle = Handle::AwaitingEnvs {
                    exec,
                    ctx,
                    path,
                    args: buf.into(),
                }
            }
            Handle::AwaitingEnvs {
                exec,
                ctx,
                path,
                args,
            } => {
                *handle = Handle::AwaitingCwd {
                    exec,
                    ctx,
                    path,
                    args,
                    envs: buf.into(),
                }
            }
            Handle::AwaitingCwd {
                exec,
                ctx,
                path,
                args,
                envs,
            } => {
                *handle = Handle::AwaitingDefaultScheme {
                    exec,
                    ctx,
                    path,
                    args,
                    envs,
                    cwd: validate_utf8(buf)?.into(),
                }
            }
            Handle::AwaitingDefaultScheme {
                exec,
                ctx,
                path,
                args,
                envs,
                cwd,
            } => {
                *handle = Handle::Finished {
                    exec,
                    ctx,
                    path,
                    args,
                    envs,
                    cwd,
                    default_scheme: validate_utf8(buf)?.into(),
                }
            }
            Handle::Finished { .. } => return Ok(0),

            Handle::Placeholder => {
                eprintln!("escalated: found placeholder handle with ID {id}");
                return Err(Error::new(EBADFD));
            }
        }
        Ok(buf.len())
    }
}
impl Scheme {
    fn on_close(&mut self, id: usize) {
        let Some(handle) = self.handles.remove(&id) else {
            eprintln!("Missing handle for {id}");
            return;
        };

        let Handle::Placeholder = handle else {
            return;
        };
    }
    fn on_sendfd(&mut self, socket: &Socket, req: &SendFdRequest) -> Result<usize> {
        let handle = self.handles.get_mut(&req.id()).ok_or(Error::new(EBADF))?;
        match std::mem::replace(handle, Handle::Placeholder) {
            Handle::AwaitingContextFd { pid } => {
                let fd = FdGuard::new({
                    let mut fd = usize::MAX;
                    req.obtain_fd(socket, FobtainFdFlags::empty(), Err(&mut fd))?;
                    fd
                });

                if !req.flags().contains(SendFdFlags::EXCLUSIVE) {
                    return Err(Error::new(EBUSY));
                }
                // FIXME: Improve the kernel proc: scheme (necessary for security), so that we can
                // ensure no other contexts can modify the context handle sent here, after this
                // file descriptor has been verified to now be exclusively owned by escalated.

                // TODO: Find a better way to read the PID than fpath
                let handle_pid = {
                    const LEN: usize = 256;

                    let mut path = [0_u8; LEN];
                    let len = syscall::fpath(*fd, &mut path)?;
                    if len > path.len() {
                        println!("escalated: too long fpath len ({len} > {LEN})");
                        return Err(Error::new(EIO));
                    }
                    assert!(path.starts_with(b"proc:"));
                    let path = &path[5..];
                    let slash = path
                        .iter()
                        .position(|c| *c == b'/')
                        .expect("malformed kernel proc: fpath");
                    let pid_str =
                        core::str::from_utf8(&path[..slash]).expect("non-UTF8 kernel proc: fpath");

                    pid_str.parse().expect("invalid kernel proc: fpath pid")
                };
                if pid != handle_pid {
                    return Err(Error::new(EACCES));
                }

                *handle = Handle::AwaitingExecFd { ctx: ContextFd(fd) }
            }
            Handle::AwaitingExecFd { ctx } => {
                let fd = FdGuard::new({
                    let mut fd = usize::MAX;
                    req.obtain_fd(socket, FobtainFdFlags::empty(), Err(&mut fd))?;
                    fd
                });

                *handle = Handle::AwaitingPath {
                    exec: ExecFd(fd),
                    ctx,
                }
            }
            old => {
                *handle = old;
                return Err(Error::new(EBADF));
            }
        }
        Ok(0)
    }
}

fn execute(
    MemoryFd(memory): &MemoryFd,
    ContextFd(context_file): ContextFd,
    ExecFd(exec_file): ExecFd,
    path: &str,
    args: &[u8],
    envs: &[u8],
    cwd: &str,
    default_scheme: &str,
) -> Result<()> {
    let (setuid, setgid) = {
        let mut stat = syscall::Stat::default();
        syscall::fstat(*exec_file, &mut stat)?;

        // TODO: Check dev so that the scheme is privileged enough to promise that a
        // higher-privilege user has indeed allowed escalation via setuid/setgid. Currently the
        // kernel forbids schemes that are not run as root, however.
        let scheme_is_adequately_privileged = |_st_dev| true;

        if !scheme_is_adequately_privileged(stat.st_dev) {
            return Err(Error::new(EPERM));
        }

        (
            Some(stat.st_uid).filter(|_| stat.st_mode & (libc::S_ISUID as u16) != 0),
            Some(stat.st_gid).filter(|_| stat.st_mode & (libc::S_ISGID as u16) != 0),
        )
    };

    if setuid.is_none() && setgid.is_none() {
        // Allowing escalated to do fexec without escalation would just allow DoS!
        return Err(Error::new(EACCES));
    }

    let setuid = setuid
        .map(|new_uid| -> Result<_> {
            Ok((new_uid, FdGuard::new(syscall::dup(*context_file, b"uid")?)))
        })
        .transpose()?;
    let setgid = setgid
        .map(|new_gid| -> Result<_> {
            Ok((new_gid, FdGuard::new(syscall::dup(*context_file, b"gid")?)))
        })
        .transpose()?;

    let address_space_fd = redox_rt::proc::fexec_impl(
        exec_file,
        context_file,
        memory,
        path.as_bytes(),
        args.rsplit(|c| *c == b'\0').filter(|a| !a.is_empty()),
        envs.rsplit(|c| *c == b'\0').filter(|a| !a.is_empty()),
        args.len() + envs.len() + cwd.len() + 1,
        &redox_rt::proc::ExtraInfo {
            cwd: Some(cwd.as_bytes()),
            default_scheme: Some(default_scheme.as_bytes()),
            sigignmask: 0,
            sigprocmask: 0,
            umask: redox_rt::sys::get_umask(),
        },
        None,
    )?;

    // Replace the address space *before* changing the UID and GID, to prevent (currently
    // impossible) race conditions that would allow the caller to run things as root before
    // becoming the setuid/setgid process.
    drop(address_space_fd);

    if let Some((new_uid, context_uid_fd)) = setuid {
        let _ = syscall::write(*context_uid_fd, new_uid.to_string().as_bytes())
            .map_err(|_| Error::new(EIO))?;
    }
    if let Some((new_gid, context_gid_fd)) = setgid {
        let _ = syscall::write(*context_gid_fd, new_gid.to_string().as_bytes())
            .map_err(|_| Error::new(EIO))?;
    }

    // TODO: SIGKILL the process if anything here fails after the process's memory has started to
    // be overwritten.

    Ok(())
}

fn main() {
    redox_daemon::Daemon::new(move |daemon| {
        let memory = MemoryFd(FdGuard::new(
            syscall::open("/scheme/memory", O_CLOEXEC).expect("failed to open `memory:`"),
        ));
        // TODO: Linux kernel audit-like logging?
        let socket = Socket::create("escalate").expect("failed to open scheme socket");

        let mut scheme = Scheme {
            next_fd: 1,
            handles: HashMap::new(),
            memory,
        };
        libredox::call::setrens(0, 0).expect("failed to setrens");
        daemon
            .ready()
            .expect("failed to signal escalate scheme readiness");

        loop {
            let Some(req) = socket
                .next_request(SignalBehavior::Restart)
                .expect("failed to get request")
            else {
                break;
            };

            let response = match req.kind() {
                RequestKind::Call(call) => call.handle_sync(&mut scheme),
                RequestKind::SendFd(req) => Response::new(scheme.on_sendfd(&socket, &req), req),
                RequestKind::OnClose { id } => {
                    scheme.on_close(id);
                    continue;
                }
                _ => continue,
            };

            socket
                .write_response(response, SignalBehavior::Restart)
                .expect("escalate: scheme write failed");
        }
        std::process::exit(0)
    })
    .expect("failed to start escalate daemon");
}
