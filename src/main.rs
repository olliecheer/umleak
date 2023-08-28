use anyhow::{Context, Result};
use blazesym::symbolize::{Process, Source, Sym, Symbolizer};
use chrono;
use libbpf_rs::libbpf_sys::bpf_object_open_opts;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Map, MapFlags, UprobeOpts};
use plain::Plain;
use std::path::PathBuf;
use structopt::StructOpt;

#[path = "bpf/.output/umleak.skel.rs"]
mod umleak;
use umleak::*;

#[repr(C)]
#[derive(Default)]
struct StackAlloc {
    stack_id: u32,
    total_size: i64,
    count: i64,
}
unsafe impl Plain for StackAlloc {}

#[derive(Debug, StructOpt)]
struct Command {
    #[structopt(long, short)]
    verbose: bool,
    #[structopt(long, short)]
    symbolize: bool,
    #[structopt(long, short, default_value = "libc.so.6")]
    glibc: String,
    #[structopt(long, short)]
    btf_file: Option<String>,
    #[structopt(long, short)]
    pid: i32,
    #[structopt(long, short, default_value = "3")]
    interval: u64,
    #[structopt(long, short, default_value = "8")]
    min_size: u64,
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    let mut skel_builder = UmleakSkelBuilder::default();
    skel_builder.obj_builder.debug(opts.verbose);

    let mut open_skel = if let Some(btf_path) = opts.btf_file {
        skel_builder.open_opts(bpf_object_open_opts {
            btf_custom_path: btf_path.as_ptr() as *const i8,
            sz: std::mem::size_of::<bpf_object_open_opts>() as u64,
            ..Default::default()
        })?
    } else {
        skel_builder.open()?
    };

    let mut open_maps = open_skel.maps_mut();
    open_maps
        .stack_traces()
        .set_value_size(64 * (std::mem::size_of::<usize>() as u32))?;

    let mut skel = open_skel.load()?;

    let _malloc_enter = skel.progs_mut().malloc_enter().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "malloc".to_string(),
            retprobe: false,
            ..Default::default()
        },
    )?;
    let _malloc_exit = skel.progs_mut().malloc_exit().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "malloc".to_string(),
            retprobe: true,
            ..Default::default()
        },
    )?;
    let _calloc_enter = skel.progs_mut().calloc_enter().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "calloc".to_string(),
            retprobe: false,
            ..Default::default()
        },
    )?;
    let _calloc_exit = skel.progs_mut().calloc_exit().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "calloc".to_string(),
            retprobe: true,
            ..Default::default()
        },
    )?;
    let _realloc_enter = skel.progs_mut().realloc_enter().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "realloc".to_string(),
            retprobe: false,
            ..Default::default()
        },
    )?;
    let _realloc_exit = skel.progs_mut().realloc_exit().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "realloc".to_string(),
            retprobe: true,
            ..Default::default()
        },
    )?;
    let _mmap_enter = skel.progs_mut().mmap_enter().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "mmap".to_string(),
            retprobe: false,
            ..Default::default()
        },
    )?;
    let _mmap_exit = skel.progs_mut().mmap_exit().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "mmap".to_string(),
            retprobe: true,
            ..Default::default()
        },
    )?;
    let _free_enter = skel.progs_mut().free_enter().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "free".to_string(),
            retprobe: false,
            ..Default::default()
        },
    )?;
    let _munmap_enter = skel.progs_mut().munmap_enter().attach_uprobe_with_opts(
        opts.pid,
        &opts.glibc,
        0,
        UprobeOpts {
            func_name: "munmap".to_string(),
            retprobe: false,
            ..Default::default()
        },
    )?;

    let maps = skel.maps();
    let stack_allocs_map = maps.stack_allocs();
    let stack_traces_map = maps.stack_traces();

    let src = Source::Process(Process::new((opts.pid as u32).into()));
    let symbolizer = Symbolizer::new();

    let do_symbolize = |addrs: &[usize]| {
        symbolizer
            .symbolize(&src, addrs)
            .with_context(|| format!("failed to symbolize stack"))
    };

    loop {
        std::thread::sleep(std::time::Duration::from_secs(opts.interval));
        print_snapshot(stack_allocs_map, stack_traces_map, opts.symbolize, opts.min_size, &do_symbolize)?;
        println!();
    }
}

fn print_snapshot(
    stack_allocs_map: &Map,
    stack_traces_map: &Map,
    enable_sym: bool,
    min_size: u64,
    do_symbolize: &dyn Fn(&[usize]) -> Result<Vec<Vec<Sym>>>,
) -> Result<()> {
    println!("{:?}", chrono::offset::Local::now());
    let mut stacks_info = Vec::<StackAlloc>::new();
    for stack_id_bytes in stack_allocs_map.keys() {
        if let Some(v_percpu) = stack_allocs_map.lookup_percpu(&stack_id_bytes, MapFlags::ANY)? {
            let mut combined = StackAlloc {
                stack_id: u32::from_ne_bytes(stack_id_bytes.try_into().expect("convert bytes to stack_id failed")),
                ..Default::default()
            };
            for v in v_percpu {
                let stack_alloc_info = plain::from_bytes::<StackAlloc>(&v)
                    .expect("convert bytes to StackAlloc failed");
                combined.count += stack_alloc_info.count;
                combined.total_size += stack_alloc_info.total_size;
            }

            if combined.total_size >= min_size as i64 {
                stacks_info.push(combined);
            }
        }
    }

    for it in stacks_info {
        println!(
            "stack_id: {}, total_size: {}, count: {}",
            it.stack_id, it.total_size, it.count
        );
        if let Some(stack_bytes) = stack_traces_map
            .lookup(&it.stack_id.to_ne_bytes(), MapFlags::ANY)
            .unwrap()
        {
            let stack = unsafe {
                std::slice::from_raw_parts(
                    stack_bytes.as_ptr() as *const usize,
                    stack_bytes.len() / std::mem::size_of::<usize>(),
                )
            };
            let syms = if enable_sym {
                do_symbolize(stack)?
            } else {
                vec![Vec::<Sym>::new(); stack.len()]
            };
            do_print_stack(stack, syms);
        }
    }
    Ok(())
}

fn do_print_stack(addrs: &[usize], syms: Vec<Vec<Sym>>) {
    for (addr, syms) in addrs.into_iter().zip(syms) {
        if *addr == 0 {
            break;
        }
        let mut addr_fmt = format!("0x{addr:#016x} :");
        if syms.is_empty() {
            println!("\t{addr_fmt} <no-symbol>");
            continue;
        }

        for (i, sym) in syms.into_iter().enumerate() {
            if i == 1 {
                addr_fmt = addr_fmt.replace(|_| true, " ");
            }
            let Sym {
                name, addr, offset, ..
            } = sym;

            let path = match (sym.dir, sym.file) {
                (Some(dir), Some(file)) => Some(dir.join(file)),
                (dir, file) => dir.or_else(|| file.map(PathBuf::from)),
            };

            let src_loc = if let (Some(path), Some(line)) = (path, sym.line) {
                if let Some(col) = sym.column {
                    format!(" {}:{line}:{col}", path.display())
                } else {
                    format!(" {}:{line}", path.display())
                }
            } else {
                String::new()
            };

            println!("\t{addr_fmt} {name} @ {addr:#x}+{offset:#x}{src_loc}");
        }
    }
}
