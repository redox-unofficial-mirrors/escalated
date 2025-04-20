// TODO: Move file descriptor number allocation to relibc, eliminating SYS_WRITE unsafety (for
// CqeOpcode::ObtainFd).
//
//#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;

use redox_rt::protocol::{ProcCall, ProcMeta};
use redox_rt::sys::proc_call;
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

#[derive(Debug)]
struct ProcFd {
    fd: FdGuard,
    fileno: usize,
}
#[derive(Debug)]
struct ThrFd {
    fd: FdGuard,
    fileno: usize,
}

struct Scheme {
    next_fd: usize,
    handles: HashMap<usize, Handle>,
    memory: MemoryFd,
}
enum Handle {
    AwaitingProcFd {
        pid: usize,
    },
    AwaitingThrFd {
        proc_fd: ProcFd,
    },
    AwaitingExecFd {
        proc_fd: ProcFd,
        thr_fd: ThrFd,
    },
    AwaitingPath {
        proc_fd: ProcFd,
        thr_fd: ThrFd,
        exec: ExecFd,
    },
    AwaitingArgs {
        proc_fd: ProcFd,
        thr_fd: ThrFd,
        exec: ExecFd,
        path: Box<str>,
    },
    AwaitingEnvs {
        exec: ExecFd,
        proc_fd: ProcFd,
        thr_fd: ThrFd,
        path: Box<str>,
        args: Box<[u8]>,
    },
    AwaitingCwd {
        exec: ExecFd,
        proc_fd: ProcFd,
        thr_fd: ThrFd,
        path: Box<str>,
        args: Box<[u8]>,
        envs: Box<[u8]>,
    },
    AwaitingDefaultScheme {
        exec: ExecFd,
        proc_fd: ProcFd,
        thr_fd: ThrFd,
        path: Box<str>,
        args: Box<[u8]>,
        envs: Box<[u8]>,
        cwd: Box<str>,
    },
    // TODO: Make cwd an fd too?
    Finished {
        exec: ExecFd,
        proc_fd: ProcFd,
        thr_fd: ThrFd,
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
            .insert(fd, Handle::AwaitingProcFd { pid: ctx.pid });

        Ok(OpenResult::ThisScheme {
            number: fd,
            flags: NewFdFlags::empty(),
        })
    }
    fn call(&mut self, id: usize, _payload: &mut [u8], _metadata: &[u64]) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let Handle::Finished {
            exec,
            proc_fd,
            thr_fd,
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
            proc_fd,
            thr_fd,
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
            old @ (Handle::AwaitingExecFd { .. }
            | Handle::AwaitingProcFd { .. }
            | Handle::AwaitingThrFd { .. }) => {
                *handle = old;
                return Err(Error::new(EINVAL));
            }
            Handle::AwaitingPath {
                exec,
                proc_fd,
                thr_fd,
            } => {
                *handle = Handle::AwaitingArgs {
                    exec,
                    proc_fd,
                    thr_fd,
                    path: validate_utf8(buf)?.into(),
                }
            }
            Handle::AwaitingArgs {
                exec,
                proc_fd,
                thr_fd,
                path,
            } => {
                *handle = Handle::AwaitingEnvs {
                    exec,
                    proc_fd,
                    thr_fd,
                    path,
                    args: buf.into(),
                }
            }
            Handle::AwaitingEnvs {
                exec,
                proc_fd,
                thr_fd,
                path,
                args,
            } => {
                *handle = Handle::AwaitingCwd {
                    exec,
                    proc_fd,
                    thr_fd,
                    path,
                    args,
                    envs: buf.into(),
                }
            }
            Handle::AwaitingCwd {
                exec,
                proc_fd,
                thr_fd,
                path,
                args,
                envs,
            } => {
                *handle = Handle::AwaitingDefaultScheme {
                    exec,
                    proc_fd,
                    thr_fd,
                    path,
                    args,
                    envs,
                    cwd: validate_utf8(buf)?.into(),
                }
            }
            Handle::AwaitingDefaultScheme {
                exec,
                proc_fd,
                thr_fd,
                path,
                args,
                envs,
                cwd,
            } => {
                *handle = Handle::Finished {
                    exec,
                    proc_fd,
                    thr_fd,
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
            Handle::AwaitingProcFd { pid } => {
                let fd = FdGuard::new({
                    let mut fd = usize::MAX;
                    req.obtain_fd(socket, FobtainFdFlags::empty(), Err(&mut fd))?;
                    fd
                });
                let proc_fd = ProcFd {
                    fd,
                    fileno: req.arg() as usize,
                };
                println!("PROC_FD {proc_fd:?}");

                // FIXME: Improve the procmgr proc scheme (necessary for security), so that we can
                // ensure no other contexts can modify the context handle sent here, after this
                // file descriptor has been verified to now be exclusively owned by escalated.

                let mut meta = ProcMeta::default();
                if syscall::read(*proc_fd.fd, unsafe { plain::as_mut_bytes(&mut meta) })?
                    != size_of::<ProcMeta>()
                {
                    return Err(Error::new(EBADF));
                }

                if pid != meta.pid as usize {
                    return Err(Error::new(EACCES));
                }

                *handle = Handle::AwaitingThrFd { proc_fd };
            }
            Handle::AwaitingThrFd { proc_fd } => {
                let fd = FdGuard::new({
                    let mut fd = usize::MAX;
                    req.obtain_fd(socket, FobtainFdFlags::empty(), Err(&mut fd))?;
                    fd
                });

                // FIXME
                //if !req.flags().contains(SendFdFlags::EXCLUSIVE) {
                //return Err(Error::new(EBUSY));
                //}

                // FIXME: use dup2 on the new thread's fdtbl to ensure proc and thr fileno point
                // exactly to the fds sent to escalated
                *handle = Handle::AwaitingExecFd {
                    proc_fd,
                    thr_fd: ThrFd {
                        fd,
                        fileno: req.arg() as usize,
                    },
                }
            }
            Handle::AwaitingExecFd { proc_fd, thr_fd } => {
                let fd = FdGuard::new({
                    let mut fd = usize::MAX;
                    req.obtain_fd(socket, FobtainFdFlags::empty(), Err(&mut fd))?;
                    fd
                });

                *handle = Handle::AwaitingPath {
                    exec: ExecFd(fd),
                    proc_fd,
                    thr_fd,
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
    ProcFd {
        fd: proc_fd,
        fileno: proc_fileno,
    }: ProcFd,
    ThrFd {
        fd: thr_fd,
        fileno: thr_fileno,
    }: ThrFd,
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

    let address_space_fd = redox_rt::proc::fexec_impl(
        exec_file,
        &thr_fd,
        &proc_fd,
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
            thr_fd: thr_fileno,
            proc_fd: proc_fileno,
            umask: redox_rt::sys::get_umask(),
        },
        None,
    )?;

    // Replace the address space *before* changing the UID and GID, to prevent (currently
    // impossible) race conditions that would allow the caller to run things as root before
    // becoming the setuid/setgid process.
    drop(address_space_fd);

    let [ruid, euid, suid] = if let Some(uid) = setuid {
        [u32::MAX, uid, uid]
    } else {
        [u32::MAX; 3] // unchanged
    };
    let [rgid, egid, sgid] = if let Some(gid) = setgid {
        [u32::MAX, gid, gid]
    } else {
        [u32::MAX; 3] // unchanged
    };
    let mut payload = [0; size_of::<u32>() * 6];
    plain::slice_from_mut_bytes(&mut payload)
        .unwrap()
        .copy_from_slice(&[ruid, euid, suid, rgid, egid, sgid]);

    if let Err(err) = proc_call(
        *proc_fd,
        &mut payload,
        CallFlags::empty(),
        &[ProcCall::SetResugid as u64],
    ) {
        eprintln!("failed to setresugid: {err}");
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
