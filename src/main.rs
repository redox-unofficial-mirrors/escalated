use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, ErrorKind, prelude::*, SeekFrom};

use syscall::data::Packet;
use syscall::error::*;
use syscall::flag::*;
use syscall::number::*;
use syscall::scheme::SchemeMut;

#[derive(Default)]
struct Scheme {
    next_fd: usize,
    handles: HashMap<usize, Handle>,
}
enum Handle {
    AwaitingPath { pid: usize },
    AwaitingArgs { pid: usize, path: Box<str> },
    AwaitingEnvs { pid: usize, path: Box<str>, args: Box<[u8]> },
    Finished { pid: usize, path: Box<str>, args: Box<[u8]>, envs: Box<[u8]> },
    Placeholder,
}

impl SchemeMut for Scheme {
    fn open(&mut self, _path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        unreachable!("open is handled manually")
    }
    fn write(&mut self, id: usize, buf: &[u8]) -> Result<usize> {
        let handle = self.handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        match std::mem::replace(handle, Handle::Placeholder) {
            Handle::AwaitingPath { pid } => *handle = Handle::AwaitingArgs { pid, path: std::str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?.into() },
            Handle::AwaitingArgs { pid, path } => *handle = Handle::AwaitingEnvs { pid, path, args: buf.into() },
            Handle::AwaitingEnvs { pid, path, args } => *handle = Handle::Finished { pid, path, args, envs: buf.into() },
            Handle::Finished { pid, path, args, envs } => execute(pid, &path, &args, &envs)?,

            Handle::Placeholder => unreachable!(),
        }
        Ok(buf.len())
    }
    fn close(&mut self, id: usize) -> Result<usize> {
        self.handles.remove(&id).ok_or(Error::new(EBADF))?;
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

#[cfg(target_arch = "x86_64")]
const PAGE_SIZE: usize = 4096;

fn mprotect_remote(socket: &mut impl Write, addr: usize, len: usize, flags: MapFlags) -> Result<()> {
    let mut grants_buf = [0_u8; 24];
    grants_buf[..8].copy_from_slice(&usize::to_ne_bytes(addr));
    grants_buf[8..16].copy_from_slice(&usize::to_ne_bytes(len));
    grants_buf[16..24].copy_from_slice(&usize::to_ne_bytes(flags.bits()));
    let _ = socket.write(&grants_buf).map_err(|_| Error::new(EIO))?;
    Ok(())
}

fn find_free_target_addr(tree: &BTreeMap<usize, usize>, requested_len: usize) -> Option<usize> {
    let mut iter = tree.iter().peekable();

    while let Some((offset, len)) = iter.next() {
        let next_offset = iter.peek().map_or(1 << 47, |(o, _)| **o);

        if (offset + len).saturating_add(requested_len) < next_offset {
            return Some(*offset + *len);
        }
    }
    None
}

fn execute(pid: usize, path: &str, args: &[u8], envs: &[u8]) -> Result<()> {
    use goblin::elf64::{header::Header, program_header::program_header64::{ProgramHeader, PT_LOAD, PF_R, PF_W, PF_X}};

    let image_file = File::open(path).map_err(|_| Error::new(EIO))?;

    let (setuid, setgid) = {
        use std::os::unix::fs::MetadataExt;
        // TODO: Check dev so that the scheme is privileged enough to promise that a
        // higher-privilege user has indeed allowed escalation via setuid/setgid.
        let metadata = image_file.metadata().map_err(|_| Error::new(EINVAL))?;
        let mode = metadata.mode();
        let uid = metadata.uid();
        let gid = metadata.gid();

        (
            Some(uid).filter(|_| mode & (libc::S_ISUID as u32) != 0),
            Some(gid).filter(|_| mode & (libc::S_ISGID as u32) != 0),
        )
    };
    let mut image_fd = BufReader::new(image_file);

    let mut memory_fd = OpenOptions::new().create(false).write(true).read(false).open(&format!("proc:{}/mem", pid)).map_err(|_| Error::new(EIO))?;
    let mut grants_fd = OpenOptions::new().create(false).write(true).read(false).open(&format!("proc:{}/grants", pid)).map_err(|_| Error::new(EIO))?;

    let mut header_bytes = [0_u8; std::mem::size_of::<Header>()];
    image_fd.read_exact(&mut header_bytes).map_err(|_| Error::new(EIO))?;
    let header = Header::parse(&header_bytes).map_err(|_| Error::new(EINVAL))?;

    image_fd.seek(SeekFrom::Start(header.e_phoff)).map_err(|_| Error::new(EIO))?;

    // Completely reset the executable's memory.
    mprotect_remote(&mut grants_fd, 0, 1 << 47, MapFlags::empty())?;

    // Never allow more than 1 MiB of program headers. TODO: Capabilities again?
    const MAX_PH_SIZE: usize = 1024 * 1024;
    let phentsize = u64::from(header.e_phentsize) as usize;
    let phnum = u64::from(header.e_phnum) as usize;
    let pheaders_size = phentsize.saturating_mul(phnum);

    if pheaders_size > MAX_PH_SIZE {
        return Err(Error::new(E2BIG));
    }
    let mut phs = vec! [0_u8; pheaders_size];

    let mut tree = BTreeMap::new();
    tree.insert(0, PAGE_SIZE);

    const BUFSZ: usize = 16384;
    let mut buf = vec! [0_u8; BUFSZ];

    image_fd.read_exact(&mut phs).map_err(|_| Error::new(EIO))?;

    for ph_idx in 0..phnum {
        let ph_bytes = &phs[ph_idx * phentsize..(ph_idx + 1) * phentsize];
        let segment: &ProgramHeader = plain::from_bytes(ph_bytes).map_err(|_| Error::new(EINVAL))?;
        let mut flags = syscall::PROT_READ;

        // W ^ X. If it is executable, do not allow it to be writable, even if requested
        if segment.p_flags & PF_X == PF_X {
            flags |= syscall::PROT_EXEC;
        } else if segment.p_flags & PF_W == PF_W {
            flags |= syscall::PROT_WRITE;
        }

        let voff = segment.p_vaddr as usize % PAGE_SIZE;
        let vaddr = segment.p_vaddr as usize - voff;
        let size =
            (segment.p_memsz as usize + voff + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;

        if segment.p_filesz > segment.p_memsz {
            return Err(Error::new(ENOEXEC));
        }
        if segment.p_type == PT_LOAD {
            mprotect_remote(&mut grants_fd, vaddr, size, flags)?;
            image_fd.seek(SeekFrom::Start(segment.p_offset)).map_err(|_| Error::new(EIO))?;
            memory_fd.seek(SeekFrom::Start(segment.p_vaddr)).map_err(|_| Error::new(EIO))?;
            for size in std::iter::repeat(BUFSZ).take((segment.p_filesz as usize) / BUFSZ).chain(Some((segment.p_filesz as usize) % BUFSZ)) {
                image_fd.read_exact(&mut buf[..size]).map_err(|_| Error::new(EIO))?;
                memory_fd.write_all(&buf[..size]).map_err(|_| Error::new(EIO))?;
            }

            if !tree.range(..=vaddr).next_back().filter(|(start, size)| **start + **size > vaddr).is_some() {
                tree.insert(vaddr, size);
            }
        }
    }
    // Setup a stack starting from the very end of the address space, and then growing downwards.
    const STACK_TOP: usize = 1 << 47;
    const STACK_SIZE: usize = 1024 * 1024;

    mprotect_remote(&mut grants_fd, STACK_TOP - STACK_SIZE, STACK_SIZE, MapFlags::PROT_READ | MapFlags::PROT_WRITE)?;
    tree.insert(STACK_TOP - STACK_SIZE, STACK_SIZE);

    let mut sp = STACK_TOP - 256;

    let mut push_outer = |memory_fd: &mut File, word: usize| {
        sp -= core::mem::size_of::<usize>();
        memory_fd.seek(SeekFrom::Start(sp as u64)).map_err(|_| Error::new(EIO))?;
        memory_fd.write_all(&usize::to_ne_bytes(word)).map_err(|_| Error::new(EIO))?;
        Ok(())
    };

    let pheaders_size_aligned = (pheaders_size+PAGE_SIZE-1)/PAGE_SIZE*PAGE_SIZE;
    let pheaders = find_free_target_addr(&tree, pheaders_size_aligned).ok_or(Error::new(ENOMEM))?;
    tree.insert(pheaders, pheaders_size_aligned);
    mprotect_remote(&mut grants_fd, pheaders, pheaders_size_aligned, MapFlags::PROT_READ)?;
    memory_fd.seek(SeekFrom::Start(pheaders as u64)).map_err(|_| Error::new(EIO))?;
    memory_fd.write_all(&phs).map_err(|_| Error::new(EIO))?;

    let mut push = |word: usize| {
        push_outer(&mut memory_fd, word)
    };

    push(0)?;
    push(AT_NULL)?;
    push(header.e_entry as usize)?;
    push(AT_ENTRY)?;
    push(pheaders)?;
    push(AT_PHDR)?;
    push(header.e_phnum as usize)?;
    push(AT_PHNUM)?;
    push(header.e_phentsize as usize)?;
    push(AT_PHENT)?;

    let total_args_envs_size = args.len() + envs.len();
    let args_envs_size_aligned = (total_args_envs_size+PAGE_SIZE-1)/PAGE_SIZE*PAGE_SIZE;
    let target_args_env_address = find_free_target_addr(&tree, args_envs_size_aligned).ok_or(Error::new(ENOMEM))?;
    mprotect_remote(&mut grants_fd, target_args_env_address, args_envs_size_aligned, MapFlags::PROT_READ | MapFlags::PROT_WRITE)?;
    tree.insert(target_args_env_address, args_envs_size_aligned);

    let mut offset = 0;

    let mut argc = 0;

    for (collection, is_args) in [(envs, false), (args, true)] {
        push_outer(&mut memory_fd, 0)?;

        for source_slice in collection.rsplit(|c| *c == b'\0').filter(|s| !s.is_empty()) {
            if is_args { argc += 1; }
            push_outer(&mut memory_fd, target_args_env_address + offset)?;
            memory_fd.seek(SeekFrom::Start((target_args_env_address + offset) as u64)).map_err(|_| Error::new(EIO))?;
            let _ = memory_fd.write_all(source_slice).map_err(|_| Error::new(EIO))?;
            offset += source_slice.len() + 1;
        }
    }

    push_outer(&mut memory_fd, argc)?;

    // TODO: Fix InterruptStack when compiling e.g. in rust-analyzer.
    #[cfg(target_os = "redox")]
    {
        let mut regs_fd = OpenOptions::new().create(false).write(true).read(false).open(&format!("proc:{}/regs/int", pid)).map_err(|_| Error::new(EIO))?;

        let mut regs = syscall::IntRegisters::default();
        regs.rsp = sp as usize;
        regs.rip = header.e_entry as usize;
        regs_fd.write_all(&regs).map_err(|_| Error::new(EIO))?;
    }

    #[cfg(target_os = "redox")]
    {
        let mut regs_fd = OpenOptions::new().create(false).write(true).read(false).open(&format!("proc:{}/regs/env", pid)).map_err(|_| Error::new(EIO))?;

        let mut regs = syscall::EnvRegisters::default();
        regs_fd.write_all(&regs).map_err(|_| Error::new(EIO))?;
    }

    if let Some(setuid) = setuid {
        std::fs::write(&format!("proc:{}/uid", pid), setuid.to_string()).map_err(|_| Error::new(EIO))?;
    }
    if let Some(setgid) = setgid {
        std::fs::write(&format!("proc:{}/gid", pid), setgid.to_string()).map_err(|_| Error::new(EIO))?;
    }

    std::fs::write(&format!("proc:{}/name", pid), path).map_err(|_| Error::new(EIO))?;

    // TODO: SIGKILL the process if anything here fails after the process's memory has started to
    // be overwritten.

    Ok(())
}

fn main() {
    syscall::Daemon::new(move |daemon| {
        // TODO: Linux kernel audit-like logging?
        let mut socket = File::create(":escalate").expect("failed to open scheme socket");
        daemon.ready().expect("failed to signal escalate scheme readiness");

        let mut packet = Packet::default();
        let mut scheme = Scheme::default();

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
        let _ = syscall::exit(0);
        unreachable!()
    }).expect("failed to start escalate daemon");
}
