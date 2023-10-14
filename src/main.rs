// TODO: Move file descriptor number allocation to relibc, eliminating SYS_WRITE unsafety (for
// SKMSG_FOBTAINFD).
//
//#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::fs::File;
use std::io::{prelude::*, ErrorKind};
use std::mem::MaybeUninit;

use syscall::data::Packet;
use syscall::error::*;
use syscall::flag::*;
use syscall::number::*;
use syscall::scheme::SchemeMut;

use redox_exec::FdGuard;

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
        pid: usize,
        ctx: ContextFd,
    },
    AwaitingPath {
        pid: usize,
        exec: ExecFd,
        ctx: ContextFd,
    },
    AwaitingArgs {
        pid: usize,
        exec: ExecFd,
        ctx: ContextFd,
        path: Box<str>,
    },
    AwaitingEnvs {
        pid: usize,
        exec: ExecFd,
        ctx: ContextFd,
        path: Box<str>,
        args: Box<[u8]>,
    },
    AwaitingCwd {
        pid: usize,
        exec: ExecFd,
        ctx: ContextFd,
        path: Box<str>,
        args: Box<[u8]>,
        envs: Box<[u8]>,
    },
    // TODO: Make cwd an fd too?
    Finished {
        pid: usize,
        exec: ExecFd,
        ctx: ContextFd,
        path: Box<str>,
        args: Box<[u8]>,
        envs: Box<[u8]>,
        cwd: Box<str>,
    },
    Placeholder,
}

impl SchemeMut for Scheme {
    fn open(&mut self, _path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        unreachable!("open is handled manually")
    }
    fn write(&mut self, id: usize, buf: &[u8]) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let validate_utf8 = |buf| std::str::from_utf8(buf).map_err(|_| Error::new(EINVAL));

        match std::mem::replace(handle, Handle::Placeholder) {
            old @ (Handle::AwaitingExecFd { .. } | Handle::AwaitingContextFd { .. }) => {
                *handle = old;
                return Err(Error::new(EINVAL));
            }
            Handle::AwaitingPath { pid, exec, ctx } => {
                *handle = Handle::AwaitingArgs {
                    pid,
                    exec,
                    ctx,
                    path: validate_utf8(buf)?.into(),
                }
            }
            Handle::AwaitingArgs {
                pid,
                exec,
                ctx,
                path,
            } => {
                *handle = Handle::AwaitingEnvs {
                    pid,
                    exec,
                    ctx,
                    path,
                    args: buf.into(),
                }
            }
            Handle::AwaitingEnvs {
                pid,
                exec,
                ctx,
                path,
                args,
            } => {
                *handle = Handle::AwaitingCwd {
                    pid,
                    exec,
                    ctx,
                    path,
                    args,
                    envs: buf.into(),
                }
            }
            Handle::AwaitingCwd {
                pid,
                exec,
                ctx,
                path,
                args,
                envs,
            } => {
                *handle = Handle::Finished {
                    pid,
                    exec,
                    ctx,
                    path,
                    args,
                    envs,
                    cwd: validate_utf8(buf)?.into(),
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
    fn close(&mut self, id: usize) -> Result<usize> {
        if let Handle::Finished {
            pid,
            exec,
            ctx,
            path,
            args,
            envs,
            cwd,
        } = self.handles.remove(&id).ok_or(Error::new(EBADF))?
        {
            execute(&self.memory, pid, ctx, exec, &path, &args, &envs, &cwd)?;
        }
        Ok(0)
    }
}
impl Scheme {
    fn ext_open(&mut self, pid: usize, _b: usize, c: usize, _d: usize) -> Result<usize> {
        // Path must be empty
        if c > 0 {
            return Err(Error::new(ENOENT));
        }
        let fd = self.next_fd;
        self.next_fd = self.next_fd.checked_add(1).ok_or(Error::new(EMFILE))?;
        self.handles.insert(fd, Handle::AwaitingContextFd { pid });

        Ok(fd)
    }
    fn ext_sendfd(
        &mut self,
        socket: &File,
        packet_id: u64,
        id: usize,
        _flags: usize,
        _arg: u64,
    ) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        match std::mem::replace(handle, Handle::Placeholder) {
            Handle::AwaitingContextFd { pid } => {
                // SAFETY: socket is a scheme socket
                let fd = unsafe { fobtainfd(socket, packet_id) };
                *handle = Handle::AwaitingExecFd {
                    pid,
                    ctx: ContextFd(fd),
                }
            }
            Handle::AwaitingExecFd { pid, ctx } => {
                let fd = unsafe { fobtainfd(socket, packet_id) };
                *handle = Handle::AwaitingPath {
                    pid,
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

// SAFETY: The socket must be a scheme socket, even though non-kernel schemes most likely can't
// write to our memory, and even though this invariant may not be enforceable by Rust's safety
// model.
unsafe fn fobtainfd(mut socket: &File, packet_id: u64) -> FdGuard {
    let mut dst_fd = MaybeUninit::uninit();
    let _ = socket
        .write(&Packet {
            id: packet_id,
            pid: 0,
            uid: 0,
            gid: 0,
            a: Error::mux(Err(Error::new(ESKMSG))),
            b: SKMSG_FOBTAINFD,
            c: dst_fd.as_mut_ptr() as usize,
            d: FobtainFdFlags::empty().bits(),
        })
        .expect("failed to run SKMSG_FOBTAINFD");
    FdGuard::new(unsafe { dst_fd.assume_init() })
}

fn execute(
    MemoryFd(memory): &MemoryFd,
    pid: usize,
    ContextFd(context_file): ContextFd,
    ExecFd(exec_file): ExecFd,
    path: &str,
    args: &[u8],
    envs: &[u8],
    cwd: &str,
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

    let address_space_fd = redox_exec::fexec_impl(
        exec_file,
        context_file,
        memory,
        path.as_bytes(),
        args.rsplit(|c| *c == b'\0').filter(|a| !a.is_empty()),
        envs.rsplit(|c| *c == b'\0').filter(|a| !a.is_empty()),
        args.len() + envs.len() + cwd.len() + 1,
        &redox_exec::ExtraInfo {
            cwd: Some(cwd.as_bytes()),
        },
        None,
    )?;

    if let Some(setuid) = setuid {
        std::fs::write(&format!("proc:{}/uid", pid), setuid.to_string())
            .map_err(|_| Error::new(EIO))?;
    }
    if let Some(setgid) = setgid {
        std::fs::write(&format!("proc:{}/gid", pid), setgid.to_string())
            .map_err(|_| Error::new(EIO))?;
    }

    drop(address_space_fd);

    // TODO: SIGKILL the process if anything here fails after the process's memory has started to
    // be overwritten.

    Ok(())
}

fn main() {
    redox_daemon::Daemon::new(move |daemon| {
        let memory = MemoryFd(FdGuard::new(
            syscall::open("memory:", O_CLOEXEC).expect("failed to open `memory:`"),
        ));
        // TODO: Linux kernel audit-like logging?
        let mut socket = File::create(":escalate").expect("failed to open scheme socket");

        let mut packet = Packet::default();
        let mut scheme = Scheme {
            next_fd: 1,
            handles: HashMap::new(),
            memory,
        };
        syscall::setrens(0, 0).expect("failed to setrens");
        daemon
            .ready()
            .expect("failed to signal escalate scheme readiness");

        'outer: loop {
            loop {
                match socket.read(&mut packet) {
                    Ok(0) => break 'outer,
                    Ok(_) => break,
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(other) => panic!("escalate: scheme failed with error: {:?}", other),
                }
            }
            // FIXME: Improved scheme trait, which provides the pid, for every single invocation.
            if packet.a == SYS_OPEN {
                packet.a = Error::mux(scheme.ext_open(packet.pid, packet.b, packet.c, packet.d));
            } else if packet.a == SYS_SENDFD {
                packet.a = Error::mux(scheme.ext_sendfd(
                    &socket,
                    packet.id,
                    packet.b,
                    packet.c,
                    u64::from(packet.uid) | (u64::from(packet.gid) << 32),
                ));
            } else {
                scheme.handle(&mut packet);
            }

            loop {
                match socket.write(&packet) {
                    Ok(0) => break 'outer,
                    Ok(_) => break,
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(other) => panic!("escalate: scheme failed with error: {:?}", other),
                }
            }
        }
        std::process::exit(0)
    })
    .expect("failed to start escalate daemon");
}
