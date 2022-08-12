// Not bad to have a memory-safe setuid/setgid implementation!
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, ErrorKind, prelude::*, SeekFrom};

use syscall::data::Packet;
use syscall::error::*;
use syscall::flag::*;
use syscall::number::*;
use syscall::scheme::SchemeMut;

use redox_exec::FdGuard;

struct Scheme {
    next_fd: usize,
    handles: HashMap<usize, Handle>,
    memory: FdGuard,
}
enum Handle {
    AwaitingPath { pid: usize },
    AwaitingArgs { pid: usize, path: Box<str> },
    AwaitingEnvs { pid: usize, path: Box<str>, args: Box<[u8]> },
    AwaitingCwd { pid: usize, path: Box<str>, args: Box<[u8]>, envs: Box<[u8]> },
    Finished { pid: usize, path: Box<str>, args: Box<[u8]>, envs: Box<[u8]>, cwd: Box<str> },
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
            Handle::AwaitingPath { pid } => *handle = Handle::AwaitingArgs { pid, path: validate_utf8(buf)?.into() },
            Handle::AwaitingArgs { pid, path } => *handle = Handle::AwaitingEnvs { pid, path, args: buf.into() },
            Handle::AwaitingEnvs { pid, path, args } => *handle = Handle::AwaitingCwd { pid, path, args, envs: buf.into() },
            Handle::AwaitingCwd { pid, path, args, envs } => *handle = Handle::Finished { pid, path, args, envs, cwd: validate_utf8(buf)?.into() },
            Handle::Finished { .. } => return Ok(0),

            Handle::Placeholder => unreachable!(),
        }
        Ok(buf.len())
    }
    fn close(&mut self, id: usize) -> Result<usize> {
        if let Handle::Finished { pid, path, args, envs, cwd } = self.handles.remove(&id).ok_or(Error::new(EBADF))? {
            execute(&self.memory, pid, &path, &args, &envs, &cwd)?;
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
        self.handles.insert(fd, Handle::AwaitingPath { pid });

        Ok(fd)
    }
}
fn execute(memory: &FdGuard, pid: usize, path: &str, args: &[u8], envs: &[u8], cwd: &str) -> Result<()> {
    let image_file = FdGuard::new(syscall::open(path, O_RDONLY | O_CLOEXEC)?);
    let open_via_dup = FdGuard::new(syscall::open(&format!("proc:{}/open_via_dup", pid), O_CLOEXEC)?);

    let (setuid, setgid) = {
        let mut stat = syscall::Stat::default();
        syscall::fstat(*image_file, &mut stat)?;

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
        image_file,
        open_via_dup,
        memory,
        path.as_bytes(),
        args.rsplit(|c| *c == b'\0').filter(|a| !a.is_empty()),
        envs.rsplit(|c| *c == b'\0').filter(|a| !a.is_empty()),
        args.len() + envs.len(),
        &redox_exec::ExtraInfo {
            cwd: Some(cwd.as_bytes()),
        },
        None,
    )?;

    if let Some(setuid) = setuid {
        std::fs::write(&format!("proc:{}/uid", pid), setuid.to_string()).map_err(|_| Error::new(EIO))?;
    }
    if let Some(setgid) = setgid {
        std::fs::write(&format!("proc:{}/gid", pid), setgid.to_string()).map_err(|_| Error::new(EIO))?;
    }

    drop(address_space_fd);

    // TODO: SIGKILL the process if anything here fails after the process's memory has started to
    // be overwritten.

    Ok(())
}

fn main() {
    redox_daemon::Daemon::new(move |daemon| {
        let memory = FdGuard::new(syscall::open("memory:", O_CLOEXEC).expect("failed to open `memory:`"));
        // TODO: Linux kernel audit-like logging?
        let mut socket = File::create(":escalate").expect("failed to open scheme socket");
        daemon.ready().expect("failed to signal escalate scheme readiness");

        let mut packet = Packet::default();
        let mut scheme = Scheme {
            next_fd: 1,
            handles: HashMap::new(),
            memory,
        };

        'outer: loop {
            loop {
                match socket.read(&mut packet) {
                    Ok(0) => break 'outer,
                    Ok(_) => break,
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(other) => panic!("escalate: scheme failed with error: {:?}", other),
                }
            }
            // FIXME: Improved scheme trait, which provides uid, gid, and pid, for every single
            // invocation.
            if packet.a == SYS_OPEN {
                packet.a = Error::mux(scheme.ext_open(packet.pid, packet.b, packet.c, packet.d));
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
    }).expect("failed to start escalate daemon");
}
