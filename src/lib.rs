use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use clap::Parser;
use fnv::{FnvBuildHasher, FnvHashSet};
use memmap2::Mmap;
use rayon::prelude::*;
use regex::bytes::Regex;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
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
}

fn parse_hex_offset(s: &str) -> Result<u32, String> {
    let hex_digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| "offset must begin with 0x or 0X".to_string())?;

    let offset =
        u32::from_str_radix(hex_digits, 16).map_err(|e| format!("failed to parse offset: {e}"))?;

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

fn get_strings(min_str_len: usize, buffer: &[u8]) -> Result<FnvHashSet<u32>, RbasefindError> {
    // Pre-allocate with estimated capacity (rough estimate: 1 string per 1KB)
    let estimated_capacity = buffer.len() / 1024;
    let mut strings =
        FnvHashSet::with_capacity_and_hasher(estimated_capacity, FnvBuildHasher::default());

    let reg_str = format!("[ -~\\t\\r\\n]{{{min_str_len},}}\x00");
    for mat in Regex::new(&reg_str)?.find_iter(buffer) {
        strings.insert(mat.start().try_into()?);
    }

    Ok(strings)
}

fn get_pointers(big_endian: bool, buffer: &[u8]) -> FnvHashSet<u32> {
    // Pre-allocate with exact capacity (one pointer per 4 bytes)
    let capacity = buffer.len() / 4;
    let mut pointers = FnvHashSet::with_capacity_and_hasher(capacity, FnvBuildHasher::default());
    let mut rdr = Cursor::new(buffer);

    loop {
        let res = if big_endian {
            rdr.read_u32::<BigEndian>()
        } else {
            rdr.read_u32::<LittleEndian>()
        };
        match res {
            Ok(v) => {
                pointers.insert(v);
            }
            Err(_) => break,
        }
    }

    pointers
}

/// Generate all base addresses to scan, aligned to the offset.
fn generate_addresses(offset: u32) -> impl ParallelIterator<Item = u32> {
    let num_addresses = (u64::from(u32::MAX) / u64::from(offset)) + 1;
    (0..num_addresses).into_par_iter().map(move |i| {
        let addr = i.saturating_mul(u64::from(offset));
        // This truncation is intentional and safe: addr is guaranteed to be <= u32::MAX
        // because we limit num_addresses based on u32::MAX / offset
        #[allow(clippy::cast_possible_truncation)]
        let result = addr as u32;
        result
    })
}

/// Count matches for a single base address.
fn count_matches_at_address(
    base_addr: u32,
    strings: &FnvHashSet<u32>,
    pointers: &FnvHashSet<u32>,
) -> usize {
    strings
        .iter()
        .filter_map(|s| s.checked_add(base_addr))
        .filter(|addr| pointers.contains(addr))
        .count()
}

/// # Errors
/// Returns an error if:
/// - The input file cannot be opened or read
/// - No strings are found in the target binary
#[allow(unsafe_code)]
pub fn run(config: &Config) -> Result<(), RbasefindError> {
    // Configure rayon thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build_global()
        .ok(); // Ignore error if already initialized

    // Memory-map the input file for efficient access
    let file = File::open(&config.filename)?;
    // SAFETY: We only read from the memory map and the file is kept open for the
    // duration. The file should not be modified externally during scanning.
    let mmap = unsafe { Mmap::map(&file)? };
    let buffer: &[u8] = &mmap;

    // Find indices of strings
    let strings = get_strings(config.min_str_len, buffer)?;

    if strings.is_empty() {
        return Err(RbasefindError::NoStringsFound);
    }
    eprintln!("Located {} strings", strings.len());

    let pointers = get_pointers(config.big_endian, buffer);
    eprintln!("Located {} pointers", pointers.len());

    let total_addresses = (u64::from(u32::MAX) / u64::from(config.offset)) + 1;
    eprintln!(
        "Scanning {} addresses with {} threads...",
        total_addresses, config.threads
    );

    // Progress tracking
    let progress_counter = AtomicU64::new(0);
    let show_progress = config.progress;

    // Find matches in parallel using rayon
    let results: Vec<(usize, u32)> = std::thread::scope(|scope| {
        // Spawn progress reporter if enabled
        let progress_handle = if show_progress {
            Some(scope.spawn(|| {
                let mut last_count = 0;
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let current = progress_counter.load(Ordering::Relaxed);
                    if current == total_addresses {
                        break;
                    }
                    if current != last_count {
                        // Precision loss is acceptable for progress display
                        #[allow(clippy::cast_precision_loss)]
                        let pct = (current as f64 / total_addresses as f64) * 100.0;
                        eprint!("\rProgress: {pct:.1}%");
                        last_count = current;
                    }
                }
                eprintln!("\rProgress: 100.0%");
            }))
        } else {
            None
        };

        let results: Vec<(usize, u32)> = generate_addresses(config.offset)
            .map(|addr| {
                let count = count_matches_at_address(addr, &strings, &pointers);
                if show_progress {
                    progress_counter.fetch_add(1, Ordering::Relaxed);
                }
                (count, addr)
            })
            .filter(|(count, _)| *count > 0)
            .collect();

        // Signal completion and wait for progress thread
        progress_counter.store(total_addresses, Ordering::Relaxed);
        if let Some(handle) = progress_handle {
            let _ = handle.join();
        }

        results
    });

    log::debug!("finished scanning");

    // Build heap from results
    let mut heap: BinaryHeap<(usize, u32)> = results.into_iter().collect();

    // Print (up to) top N results
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
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ==================== parse_hex_offset tests ====================

    #[test]
    fn test_parse_hex_offset_valid() {
        assert_eq!(parse_hex_offset("0x1000").unwrap(), 0x1000);
        assert_eq!(parse_hex_offset("0X1000").unwrap(), 0x1000);
        assert_eq!(parse_hex_offset("0x100").unwrap(), 0x100);
        assert_eq!(parse_hex_offset("0x80000000").unwrap(), 0x8000_0000);
    }

    #[test]
    fn test_parse_hex_offset_invalid_prefix() {
        assert!(parse_hex_offset("1000").is_err());
        assert!(parse_hex_offset("x1000").is_err());
    }

    #[test]
    fn test_parse_hex_offset_not_power_of_two() {
        assert!(parse_hex_offset("0x1001").is_err());
        assert!(parse_hex_offset("0x3").is_err());
        assert!(parse_hex_offset("0x0").is_err()); // zero is not a power of 2
    }

    // ==================== get_strings tests ====================

    #[test]
    fn test_get_strings_finds_null_terminated() {
        // Create a buffer with a null-terminated string at offset 0x10
        let mut buffer = vec![0u8; 0x100];
        let test_string = b"Hello World Test String\x00";
        buffer[0x10..0x10 + test_string.len()].copy_from_slice(test_string);

        let strings = get_strings(10, &buffer).unwrap();
        assert!(strings.contains(&0x10));
    }

    #[test]
    fn test_get_strings_respects_min_length() {
        let mut buffer = vec![0u8; 0x100];

        // Short string (9 chars) - should NOT be found with min_len=10
        let short = b"Short str\x00";
        buffer[0x10..0x10 + short.len()].copy_from_slice(short);

        // Long string (15 chars) - should be found
        let long = b"This is a longg\x00";
        buffer[0x50..0x50 + long.len()].copy_from_slice(long);

        let strings = get_strings(10, &buffer).unwrap();
        assert!(!strings.contains(&0x10), "Short string should not be found");
        assert!(strings.contains(&0x50), "Long string should be found");
    }

    #[test]
    fn test_get_strings_multiple() {
        let mut buffer = vec![0u8; 0x200];

        let str1 = b"First string here\x00";
        let str2 = b"Second string here\x00";
        let str3 = b"Third string here\x00";

        buffer[0x00..str1.len()].copy_from_slice(str1);
        buffer[0x80..0x80 + str2.len()].copy_from_slice(str2);
        buffer[0x100..0x100 + str3.len()].copy_from_slice(str3);

        let strings = get_strings(10, &buffer).unwrap();
        assert_eq!(strings.len(), 3);
        assert!(strings.contains(&0x00));
        assert!(strings.contains(&0x80));
        assert!(strings.contains(&0x100));
    }

    #[test]
    fn test_get_strings_empty_buffer() {
        let buffer = vec![];
        let strings = get_strings(10, &buffer).unwrap();
        assert!(strings.is_empty());
    }

    // ==================== get_pointers tests ====================

    #[test]
    fn test_get_pointers_little_endian() {
        // Little endian: 0x12345678 stored as [0x78, 0x56, 0x34, 0x12]
        let buffer = vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE];

        let pointers = get_pointers(false, &buffer);
        assert!(pointers.contains(&0x1234_5678));
        assert!(pointers.contains(&0xDEAD_BEEF));
    }

    #[test]
    fn test_get_pointers_big_endian() {
        // Big endian: 0x12345678 stored as [0x12, 0x34, 0x56, 0x78]
        let buffer = vec![0x12, 0x34, 0x56, 0x78, 0xDE, 0xAD, 0xBE, 0xEF];

        let pointers = get_pointers(true, &buffer);
        assert!(pointers.contains(&0x1234_5678));
        assert!(pointers.contains(&0xDEAD_BEEF));
    }

    #[test]
    fn test_get_pointers_partial_last() {
        // Buffer with 5 bytes - last byte should be ignored
        let buffer = vec![0x78, 0x56, 0x34, 0x12, 0xFF];

        let pointers = get_pointers(false, &buffer);
        assert_eq!(pointers.len(), 1);
        assert!(pointers.contains(&0x1234_5678));
    }

    #[test]
    fn test_get_pointers_deduplication() {
        // Same pointer value repeated
        let buffer = vec![
            0x78, 0x56, 0x34, 0x12, // 0x12345678
            0x78, 0x56, 0x34, 0x12, // 0x12345678 again
        ];

        let pointers = get_pointers(false, &buffer);
        assert_eq!(pointers.len(), 1); // Should be deduplicated
    }

    // ==================== generate_addresses tests ====================

    #[test]
    fn test_generate_addresses() {
        let addrs: Vec<u32> = generate_addresses(0x8000_0000).collect();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], 0);
        assert_eq!(addrs[1], 0x8000_0000);

        // Test with smaller offset
        let addrs: Vec<u32> = generate_addresses(0x4000_0000).collect();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], 0);
        assert_eq!(addrs[1], 0x4000_0000);
        assert_eq!(addrs[2], 0x8000_0000);
        assert_eq!(addrs[3], 0xC000_0000);
    }

    #[test]
    fn test_generate_addresses_small_offset() {
        let addrs: Vec<u32> = generate_addresses(0x1000).collect();
        // (0xFFFFFFFF / 0x1000) + 1 = 0x100000
        assert_eq!(addrs.len(), 0x10_0000);
        assert_eq!(addrs[0], 0);
        assert_eq!(addrs[1], 0x1000);
        assert_eq!(addrs[0x1000], 0x100_0000);
    }

    // ==================== count_matches_at_address tests ====================

    #[test]
    fn test_count_matches() {
        let mut strings = FnvHashSet::default();
        strings.insert(0x100);
        strings.insert(0x200);

        let mut pointers = FnvHashSet::default();
        pointers.insert(0x1100); // matches string 0x100 at base 0x1000
        pointers.insert(0x1200); // matches string 0x200 at base 0x1000
        pointers.insert(0x2100); // matches string 0x100 at base 0x2000

        assert_eq!(count_matches_at_address(0x1000, &strings, &pointers), 2);
        assert_eq!(count_matches_at_address(0x2000, &strings, &pointers), 1);
        assert_eq!(count_matches_at_address(0x3000, &strings, &pointers), 0);
    }

    #[test]
    fn test_count_matches_overflow_protection() {
        // Test that we don't panic on overflow
        let mut strings = FnvHashSet::default();
        strings.insert(0xFFFF_FFF0); // Near u32::MAX

        let mut pointers = FnvHashSet::default();
        pointers.insert(0x0000_0010);

        // This would overflow without checked_add
        assert_eq!(count_matches_at_address(0x1000, &strings, &pointers), 0);
    }

    // ==================== Integration tests ====================

    /// Create a test binary with known strings and pointers that should match at a specific base
    fn create_test_binary(base_addr: u32, string_offsets: &[u32]) -> Vec<u8> {
        let mut buffer = vec![0u8; 0x1000];

        // Place strings at the given offsets
        for (i, &offset) in string_offsets.iter().enumerate() {
            let string = format!("Test string number {i:03}\x00");
            let start = offset as usize;
            if start + string.len() <= buffer.len() {
                buffer[start..start + string.len()].copy_from_slice(string.as_bytes());
            }
        }

        // Place pointers that point to (base_addr + string_offset) for each string
        let pointer_start = 0x800usize;
        for (i, &offset) in string_offsets.iter().enumerate() {
            let ptr_value = base_addr.wrapping_add(offset);
            let ptr_offset = pointer_start + i * 4;
            if ptr_offset + 4 <= buffer.len() {
                buffer[ptr_offset..ptr_offset + 4].copy_from_slice(&ptr_value.to_le_bytes());
            }
        }

        buffer
    }

    #[test]
    fn test_integration_finds_correct_base() {
        let base_addr = 0x0040_0000u32;
        let string_offsets = vec![0x100, 0x200, 0x300];
        let buffer = create_test_binary(base_addr, &string_offsets);

        let strings = get_strings(10, &buffer).unwrap();
        let pointers = get_pointers(false, &buffer);

        // The base address should have the most matches
        let count = count_matches_at_address(base_addr, &strings, &pointers);
        assert_eq!(count, 3, "Should find all 3 string/pointer matches");

        // Other addresses should have fewer or no matches
        let wrong_count = count_matches_at_address(0x0050_0000, &strings, &pointers);
        assert_eq!(wrong_count, 0, "Wrong base should have no matches");
    }

    #[test]
    fn test_integration_with_file() {
        let base_addr = 0x0010_0000u32;
        let string_offsets = vec![0x100, 0x180, 0x200, 0x280, 0x300];
        let buffer = create_test_binary(base_addr, &string_offsets);

        // Write to temp file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&buffer).unwrap();
        temp_file.flush().unwrap();

        let config = Config {
            filename: temp_file.path().to_path_buf(),
            big_endian: false,
            min_str_len: 10,
            max_matches: 10,
            offset: 0x1000,
            progress: false,
            threads: 1,
        };

        // Run should succeed
        let result = run(&config);
        assert!(result.is_ok(), "run() should succeed: {result:?}");
    }

    #[test]
    fn test_integration_no_strings_error() {
        // Create a file with no valid strings
        let buffer = vec![0u8; 0x100];

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&buffer).unwrap();
        temp_file.flush().unwrap();

        let config = Config {
            filename: temp_file.path().to_path_buf(),
            big_endian: false,
            min_str_len: 10,
            max_matches: 10,
            offset: 0x1000,
            progress: false,
            threads: 1,
        };

        let result = run(&config);
        assert!(matches!(result, Err(RbasefindError::NoStringsFound)));
    }

    #[test]
    fn test_integration_file_not_found() {
        let config = Config {
            filename: PathBuf::from("/nonexistent/file/path"),
            big_endian: false,
            min_str_len: 10,
            max_matches: 10,
            offset: 0x1000,
            progress: false,
            threads: 1,
        };

        let result = run(&config);
        assert!(matches!(result, Err(RbasefindError::Io(_))));
    }

    #[test]
    fn test_integration_big_endian() {
        let mut buffer = vec![0u8; 0x1000];

        // Place a string at offset 0x100
        let string = b"Big endian test string\x00";
        buffer[0x100..0x100 + string.len()].copy_from_slice(string);

        // Place a big-endian pointer at 0x800 pointing to base + 0x100
        let base_addr = 0x0080_0000u32;
        let ptr_value = base_addr + 0x100;
        buffer[0x800..0x804].copy_from_slice(&ptr_value.to_be_bytes());

        let strings = get_strings(10, &buffer).unwrap();
        let pointers = get_pointers(true, &buffer); // big endian

        let count = count_matches_at_address(base_addr, &strings, &pointers);
        assert_eq!(count, 1);
    }

    // ==================== Pre-allocation tests ====================

    #[test]
    fn test_pre_allocation() {
        // Test that pre-allocation works without panicking
        let buffer = vec![0u8; 10000];
        let strings = get_strings(10, &buffer).unwrap();
        assert!(strings.is_empty()); // No valid strings in zero buffer

        let pointers = get_pointers(false, &buffer);
        assert_eq!(pointers.len(), 1); // All zeros = one unique pointer (0)
    }
}
