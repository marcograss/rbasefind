use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use clap::Parser;
use fnv::FnvHashSet;
use pbr::MultiBar;
use regex::bytes::Regex;
use std::collections::BinaryHeap;
use std::io::{sink, stderr, Cursor, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RbasefindError {
    #[error("failed to read input file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse regex: {0}")]
    Regex(#[from] regex::Error),

    #[error("binary too large for 32-bit addressing")]
    BinaryTooLarge(#[from] std::num::TryFromIntError),

    #[error("no strings found in target binary")]
    NoStringsFound,

    #[error("thread panicked during matching")]
    ThreadPanic,

    #[error("thread error: {0}")]
    ThreadError(String),

    #[error("invalid interval index")]
    InvalidIntervalIndex,

    #[error("invalid offset: must be a power of 2")]
    InvalidOffset,
}

fn parse_hex_offset(s: &str) -> Result<u32, String> {
    let hex_digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| "offset must begin with 0x or 0X".to_string())?;

    let offset = u32::from_str_radix(hex_digits, 16)
        .map_err(|e| format!("failed to parse offset: {e}"))?;

    if offset.count_ones() != 1 {
        return Err("offset must be a power of 2".to_string());
    }

    Ok(offset)
}

#[derive(Parser, Debug)]
#[command(
    name = "rbasefind",
    version,
    author = "Scott G. <github.scott@gmail.com>",
    about = "Scan a flat 32-bit binary and attempt to brute-force the base address via \
             string/pointer comparison. Based on the excellent basefind.py by mncoppola."
)]
pub struct Config {
    /// The input binary to scan
    #[arg()]
    pub filename: PathBuf,

    /// Interpret as big-endian (default is little)
    #[arg(short = 'b', long)]
    pub big_endian: bool,

    /// Minimum string search length
    #[arg(short = 'm', long, default_value = "10")]
    pub min_str_len: usize,

    /// Maximum matches to display
    #[arg(short = 'n', long, default_value = "10")]
    pub max_matches: usize,

    /// Scan every N (power of 2) addresses
    #[arg(short = 'o', long, default_value = "0x1000", value_parser = parse_hex_offset)]
    pub offset: u32,

    /// Show progress
    #[arg(short = 'p', long)]
    pub progress: bool,

    /// Number of threads to spawn (default is number of cpu cores)
    #[arg(short = 't', long, default_value_t = default_threads())]
    pub threads: usize,
}

fn default_threads() -> usize {
    thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

pub struct Interval {
    start_addr: u32,
    end_addr: u32,
}

impl Interval {
    fn get_range(index: usize, max_threads: usize, offset: u32) -> Result<Self, RbasefindError> {
        if index >= max_threads {
            return Err(RbasefindError::InvalidIntervalIndex);
        }

        if offset.count_ones() != 1 {
            return Err(RbasefindError::InvalidOffset);
        }

        let mut start_addr =
            index as u64 * u64::from(u32::MAX).div_ceil(max_threads as u64);
        let mut end_addr =
            (index as u64 + 1) * u64::from(u32::MAX).div_ceil(max_threads as u64);

        // Mask the address such that it's aligned to the 2^N offset.
        start_addr &= !(u64::from(offset) - 1);
        if end_addr >= u64::from(u32::MAX) {
            end_addr = u64::from(u32::MAX);
        } else {
            end_addr &= !(u64::from(offset) - 1);
        }

        let interval = Self {
            start_addr: start_addr.try_into()?,
            end_addr: end_addr.try_into()?,
        };

        Ok(interval)
    }
}

fn get_strings(min_str_len: usize, buffer: &[u8]) -> Result<FnvHashSet<u32>, RbasefindError> {
    let mut strings = FnvHashSet::default();

    let reg_str = format!("[ -~\\t\\r\\n]{{{min_str_len},}}\x00");
    for mat in Regex::new(&reg_str)?.find_iter(buffer) {
        strings.insert(mat.start().try_into()?);
    }

    Ok(strings)
}

fn get_pointers(big_endian: bool, buffer: &[u8]) -> FnvHashSet<u32> {
    let mut pointers = FnvHashSet::default();
    let mut rdr = Cursor::new(buffer);
    loop {
        let res = if big_endian {
            rdr.read_u32::<BigEndian>()
        } else {
            rdr.read_u32::<LittleEndian>()
        };
        match res {
            Ok(v) => pointers.insert(v),
            Err(_) => break,
        };
    }

    pointers
}

fn find_matches(
    threads: usize,
    offset: u32,
    strings: &FnvHashSet<u32>,
    pointers: &FnvHashSet<u32>,
    scan_interval: usize,
    pb: &mut pbr::ProgressBar<pbr::Pipe>,
) -> Result<BinaryHeap<(usize, u32)>, RbasefindError> {
    let interval = Interval::get_range(scan_interval, threads, offset)?;
    let mut current_addr = interval.start_addr;
    let mut heap = BinaryHeap::<(usize, u32)>::new();
    pb.total = u64::from((interval.end_addr - interval.start_addr) / offset);
    while current_addr <= interval.end_addr {
        let mut news = FnvHashSet::default();
        for s in strings {
            match s.checked_add(current_addr) {
                Some(add) => news.insert(add),
                None => continue,
            };
        }
        let intersection: FnvHashSet<_> = news.intersection(pointers).collect();
        if !intersection.is_empty() {
            heap.push((intersection.len(), current_addr));
        }
        match current_addr.checked_add(offset) {
            Some(_) => current_addr += offset,
            None => break,
        }
        pb.inc();
    }

    log::debug!("thread with interval {scan_interval} done");

    Ok(heap)
}

/// # Errors
/// Returns an error if:
/// - The input file cannot be opened or read
/// - No strings are found in the target binary
/// - A spawned thread panics or returns an error during matching
pub fn run(config: &Config) -> Result<(), RbasefindError> {
    // Read in the input file. We jam it all into memory for now.
    let buffer = std::fs::read(&config.filename)?;

    // Find indices of strings.
    let strings = get_strings(config.min_str_len, &buffer)?;

    if strings.is_empty() {
        return Err(RbasefindError::NoStringsFound);
    }
    eprintln!("Located {} strings", strings.len());

    let pointers = get_pointers(config.big_endian, &buffer);
    eprintln!("Located {} pointers", pointers.len());

    let mut children = vec![];
    let threads = config.threads;
    let offset = config.offset;
    let shared_strings = Arc::new(strings);
    let shared_pointers = Arc::new(pointers);

    let bar_output: Box<dyn Write + Send + Sync> = if config.progress {
        Box::new(stderr())
    } else {
        Box::new(sink())
    };

    log::debug!("bar_output is {}", config.progress);

    let mb = MultiBar::on(bar_output);
    eprintln!("Scanning with {threads} threads...");
    for i in 0..threads {
        let mut pb = mb.create_bar(100);
        pb.show_message = true;
        pb.set_max_refresh_rate(Some(Duration::from_millis(100)));
        let child_strings = Arc::clone(&shared_strings);
        let child_pointers = Arc::clone(&shared_pointers);
        children.push(thread::spawn(move || {
            let res = find_matches(threads, offset, &child_strings, &child_pointers, i, &mut pb);
            pb.finish();
            res
        }));
    }
    thread::spawn(move || {
        mb.listen();
    });

    log::debug!("starting to merge all heaps");
    // Merge all of the heaps.
    let mut heap = BinaryHeap::<(usize, u32)>::new();
    for child in children {
        let thread_result = child.join().map_err(|_| RbasefindError::ThreadPanic)?;
        let mut matches = thread_result?;
        heap.append(&mut matches);
    }

    log::debug!("finished merging all heaps");

    // Print (up to) top N results.
    for _ in 0..config.max_matches {
        let Some((count, addr)) = heap.pop() else {
            break;
        };
        println!("0x{addr:08x}: {count}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_matches_invalid_interval() {
        let result = Interval::get_range(1, 1, 0x1000);
        assert!(matches!(result, Err(RbasefindError::InvalidIntervalIndex)));
    }

    #[test]
    fn find_matches_single_cpu_interval_0() {
        let interval = Interval::get_range(0, 1, 0x1000).unwrap();
        assert_eq!(interval.start_addr, u32::MIN);
        assert_eq!(interval.end_addr, u32::MAX);
    }

    #[test]
    fn find_matches_double_cpu_interval_0() {
        let interval = Interval::get_range(0, 2, 0x1000).unwrap();
        assert_eq!(interval.start_addr, u32::MIN);
        assert_eq!(interval.end_addr, 0x8000_0000);
    }

    #[test]
    fn find_matches_double_cpu_interval_1() {
        let interval = Interval::get_range(1, 2, 0x1000).unwrap();
        assert_eq!(interval.start_addr, 0x8000_0000);
        assert_eq!(interval.end_addr, u32::MAX);
    }

    #[test]
    fn find_matches_triple_cpu_interval_0() {
        let interval = Interval::get_range(0, 3, 0x1000).unwrap();
        assert_eq!(interval.start_addr, u32::MIN);
        assert_eq!(interval.end_addr, 0x5555_5000);
    }

    #[test]
    fn find_matches_triple_cpu_interval_1() {
        let interval = Interval::get_range(1, 3, 0x1000).unwrap();
        assert_eq!(interval.start_addr, 0x5555_5000);
        assert_eq!(interval.end_addr, 0xAAAA_A000);
    }

    #[test]
    fn find_matches_triple_cpu_interval_2() {
        let interval = Interval::get_range(2, 3, 0x1000).unwrap();
        assert_eq!(interval.start_addr, 0xAAAA_A000);
        assert_eq!(interval.end_addr, u32::MAX);
    }
}
