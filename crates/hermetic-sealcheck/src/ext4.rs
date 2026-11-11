//! Ext4 filesystem image verification for D4 timestamps (TR-SC-7, TR-SEAL-7).
//!
//! Checks that no inode or superblock timestamp in an ext4 image is later than `T_clock`.

use std::path::Path;
use time::OffsetDateTime;

use crate::scan::{Finding, Severity, Visibility};

const SUPERBLOCK_OFFSET: usize = 1024;
const SUPERBLOCK_SIZE: usize = 1024;
const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_BG_INODE_UNINIT: u16 = 0x0001;
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
const EXT4_EA_INODE_FL: u32 = 0x0020_0000;

#[derive(Debug)]
struct Ext4Malformed(String);

/// Decode extra time bits using the kernel's `ext4_decode_extra_time` algorithm.
///
/// The lower 2 bits of `extra` extend the 32-bit signed seconds field by 2 bits.
/// The upper 30 bits of `extra` store the nanoseconds.
fn ext4_decode_extra_time(base: u32, extra: u32) -> (i64, u32) {
    let mut sec = (base as i32) as i64;
    let epoch = (extra & 3) as u64;
    if epoch != 0 {
        sec += (epoch << 32) as i64;
    }
    let nsec = (extra & 0xFFFF_FFFC) >> 2;
    (sec, nsec)
}

/// Decode superblock timestamp with optional `_hi` extension byte.
fn decode_sb_time(sb: &[u8], lo_off: usize, hi_off: usize) -> i64 {
    if lo_off + 4 > sb.len() {
        return 0;
    }
    let lo = u32::from_le_bytes([sb[lo_off], sb[lo_off + 1], sb[lo_off + 2], sb[lo_off + 3]]);
    let hi = if hi_off < sb.len() { sb[hi_off] } else { 0 };
    if lo == 0 && hi == 0 {
        return 0;
    }
    (((hi as u64) << 32) | (lo as u64)) as i64
}

fn format_ext4_time(sec: i64, nsec: u32) -> String {
    let total_nanos = (sec as i128) * 1_000_000_000 + (nsec as i128);
    match OffsetDateTime::from_unix_timestamp_nanos(total_nanos) {
        Ok(dt) => dt
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| dt.to_string()),
        Err(_) => format!("{sec}s"),
    }
}

fn parse_ext4(
    image_display: &str,
    data: &[u8],
    t_clock: OffsetDateTime,
) -> Result<Vec<Finding>, Ext4Malformed> {
    if data.len() < SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE {
        return Err(Ext4Malformed(format!(
            "image too small for superblock ({} < 2048 bytes)",
            data.len()
        )));
    }

    let sb = &data[SUPERBLOCK_OFFSET..SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE];

    // Magic check
    let magic = u16::from_le_bytes([sb[0x38], sb[0x39]]);
    if magic != EXT4_MAGIC {
        return Err(Ext4Malformed(format!(
            "bad magic 0x{magic:04x}, expected 0xef53"
        )));
    }

    // Block size: 1024 << s_log_block_size
    let s_log_block_size = u32::from_le_bytes([sb[0x18], sb[0x19], sb[0x1A], sb[0x1B]]);
    if s_log_block_size > 6 {
        return Err(Ext4Malformed(format!(
            "invalid block size log {s_log_block_size}"
        )));
    }
    let block_size = 1024u64 << s_log_block_size;

    // Inode size
    let s_inode_size = u16::from_le_bytes([sb[0x58], sb[0x59]]) as usize;
    if s_inode_size < 128 || !s_inode_size.is_power_of_two() || (s_inode_size as u64) > block_size {
        return Err(Ext4Malformed(format!("invalid inode size {s_inode_size}")));
    }

    // Inodes per group and total inodes
    let s_inodes_per_group = u32::from_le_bytes([sb[0x28], sb[0x29], sb[0x2A], sb[0x2B]]) as u64;
    let s_inodes_count = u32::from_le_bytes([sb[0x00], sb[0x01], sb[0x02], sb[0x03]]) as u64;
    if s_inodes_per_group == 0 || s_inodes_count == 0 {
        return Err(Ext4Malformed(
            "inodes per group or total inodes is zero".into(),
        ));
    }
    if s_inodes_per_group > s_inodes_count {
        return Err(Ext4Malformed(
            "inodes per group exceeds total inodes".into(),
        ));
    }
    if s_inodes_per_group > block_size.saturating_mul(8) {
        return Err(Ext4Malformed(format!(
            "huge inodes per group {s_inodes_per_group} exceeds bitmap capacity"
        )));
    }
    if s_inodes_per_group.saturating_mul(s_inode_size as u64) > data.len() as u64 {
        return Err(Ext4Malformed(
            "inodes per group table exceeds image size".into(),
        ));
    }

    // 64-bit feature and descriptor size
    let s_feature_incompat = u32::from_le_bytes([sb[0x60], sb[0x61], sb[0x62], sb[0x63]]);
    let is_64bit = (s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0;
    let s_desc_size = u16::from_le_bytes([sb[0xFE], sb[0xFF]]) as usize;
    let desc_size = if is_64bit {
        if s_desc_size != 0 {
            s_desc_size
        } else {
            64
        }
    } else {
        32
    };
    if desc_size < 32 || !desc_size.is_power_of_two() || (desc_size as u64) > block_size {
        return Err(Ext4Malformed(format!(
            "invalid descriptor size {desc_size}"
        )));
    }
    if is_64bit && desc_size < 64 {
        return Err(Ext4Malformed(format!(
            "64-bit filesystem descriptor size {desc_size} < 64"
        )));
    }

    // Blocks per group and total blocks
    let s_blocks_per_group = u32::from_le_bytes([sb[0x20], sb[0x21], sb[0x22], sb[0x23]]) as u64;
    if s_blocks_per_group == 0 {
        return Err(Ext4Malformed("blocks per group is zero".into()));
    }
    let s_blocks_count_lo = u32::from_le_bytes([sb[0x04], sb[0x05], sb[0x06], sb[0x07]]) as u64;
    let s_blocks_count_hi = if is_64bit {
        u32::from_le_bytes([sb[0x150], sb[0x151], sb[0x152], sb[0x153]]) as u64
    } else {
        0
    };
    let total_blocks = s_blocks_count_lo | (s_blocks_count_hi << 32);
    if total_blocks == 0 {
        return Err(Ext4Malformed("total blocks is zero".into()));
    }

    // Group count calculation
    let s_first_data_block = u32::from_le_bytes([sb[0x14], sb[0x15], sb[0x16], sb[0x17]]) as u64;
    let group_count = total_blocks
        .saturating_sub(s_first_data_block)
        .div_ceil(s_blocks_per_group);
    let group_count_from_inodes = s_inodes_count.div_ceil(s_inodes_per_group);
    if group_count == 0 || group_count_from_inodes == 0 {
        return Err(Ext4Malformed("group count is zero".into()));
    }
    if group_count != group_count_from_inodes {
        return Err(Ext4Malformed(format!(
            "group count mismatch: {group_count} from blocks, {group_count_from_inodes} from inodes"
        )));
    }

    // Check bounds: descriptor table and total blocks against image size
    let gdt_block = s_first_data_block + 1;
    let gdt_offset = gdt_block.saturating_mul(block_size);
    let gdt_size = group_count.saturating_mul(desc_size as u64);
    if gdt_offset.saturating_add(gdt_size) > data.len() as u64 {
        return Err(Ext4Malformed(
            "descriptor table past the end of image".into(),
        ));
    }
    if total_blocks.saturating_mul(block_size) > data.len() as u64 {
        return Err(Ext4Malformed("group count past the file".into()));
    }

    let t_clock_secs = t_clock.unix_timestamp();
    let t_clock_nanos = t_clock.nanosecond();
    let t_clock_str = t_clock
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t_clock.to_string());

    let mut findings = Vec::new();

    // 1. Superblock times
    let sb_times = [
        ("s_mtime", 0x2C, 0x275),
        ("s_wtime", 0x30, 0x274),
        ("s_mkfs_time", 0x108, 0x276),
        ("s_lastcheck", 0x40, 0x277),
        ("s_first_error_time", 0x198, 0x278),
        ("s_last_error_time", 0x1CC, 0x279),
    ];

    for (field, lo_off, hi_off) in sb_times {
        let sec = decode_sb_time(sb, lo_off, hi_off);
        if sec == 0 {
            // A zero time is "unset", not a violation
            continue;
        }
        let is_later = sec > t_clock_secs;
        if is_later {
            let time_str = format_ext4_time(sec, 0);
            findings.push(Finding {
                detector: "D4".into(),
                channel: "superblock".into(),
                path: format!("{image_display}#superblock/{field}"),
                visibility: Visibility::AgentVisible,
                severity: Severity::Gate,
                confidence: 1.0,
                hunk: None,
                evidence: vec![format!("{field} {time_str} > T_clock {t_clock_str}")],
            });
        }
    }

    // 2. Inode times
    for g in 0..group_count {
        let gd_offset = match usize::try_from(gdt_offset + g * (desc_size as u64)) {
            Ok(off) => off,
            Err(_) => return Err(Ext4Malformed("group descriptor offset overflow".into())),
        };
        let gd = match data.get(gd_offset..gd_offset + desc_size) {
            Some(slice) => slice,
            None => return Err(Ext4Malformed("group descriptor out of bounds".into())),
        };

        let bg_flags = u16::from_le_bytes([gd[0x12], gd[0x13]]);
        if (bg_flags & EXT4_BG_INODE_UNINIT) != 0 {
            // Skip uninitialized inode table
            continue;
        }

        let bg_inode_bitmap_lo =
            u32::from_le_bytes([gd[0x04], gd[0x05], gd[0x06], gd[0x07]]) as u64;
        let bg_inode_bitmap_hi = if is_64bit && desc_size >= 64 {
            u32::from_le_bytes([gd[0x24], gd[0x25], gd[0x26], gd[0x27]]) as u64
        } else {
            0
        };
        let inode_bitmap_block = bg_inode_bitmap_lo | (bg_inode_bitmap_hi << 32);

        let bg_inode_table_lo = u32::from_le_bytes([gd[0x08], gd[0x09], gd[0x0A], gd[0x0B]]) as u64;
        let bg_inode_table_hi = if is_64bit && desc_size >= 64 {
            u32::from_le_bytes([gd[0x28], gd[0x29], gd[0x2A], gd[0x2B]]) as u64
        } else {
            0
        };
        let inode_table_block = bg_inode_table_lo | (bg_inode_table_hi << 32);

        let bitmap_offset = match usize::try_from(inode_bitmap_block.saturating_mul(block_size)) {
            Ok(off) => off,
            Err(_) => return Err(Ext4Malformed("bitmap offset overflow".into())),
        };
        let bitmap_slice = match data.get(bitmap_offset..bitmap_offset + (block_size as usize)) {
            Some(s) => s,
            None => return Err(Ext4Malformed("inode bitmap out of bounds".into())),
        };

        let itable_size =
            match usize::try_from(s_inodes_per_group.saturating_mul(s_inode_size as u64)) {
                Ok(sz) => sz,
                Err(_) => return Err(Ext4Malformed("inode table size overflow".into())),
            };
        let itable_offset = match usize::try_from(inode_table_block.saturating_mul(block_size)) {
            Ok(off) => off,
            Err(_) => return Err(Ext4Malformed("inode table offset overflow".into())),
        };
        let itable_slice = match data.get(itable_offset..itable_offset + itable_size) {
            Some(s) => s,
            None => return Err(Ext4Malformed("inode table out of bounds".into())),
        };

        for i in 0..s_inodes_per_group {
            let inode_num = g * s_inodes_per_group + i + 1;
            if inode_num > s_inodes_count {
                break;
            }

            let byte_idx = (i / 8) as usize;
            let bit_idx = (i % 8) as u8;
            if byte_idx >= bitmap_slice.len() {
                return Err(Ext4Malformed("inode bitmap index out of bounds".into()));
            }

            if (bitmap_slice[byte_idx] & (1 << bit_idx)) == 0 {
                // Inode not in use
                continue;
            }

            let in_off = (i as usize) * s_inode_size;
            let inode_slice = match itable_slice.get(in_off..in_off + s_inode_size) {
                Some(s) => s,
                None => return Err(Ext4Malformed("inode slice out of bounds".into())),
            };

            // i_dtime at 0x14: only for deleted inodes, which aren't in use, so skip
            let dtime = u32::from_le_bytes([
                inode_slice[0x14],
                inode_slice[0x15],
                inode_slice[0x16],
                inode_slice[0x17],
            ]);
            if dtime != 0 {
                continue;
            }

            let flags = u32::from_le_bytes([
                inode_slice[0x20],
                inode_slice[0x21],
                inode_slice[0x22],
                inode_slice[0x23],
            ]);
            let is_ea_inode = (flags & EXT4_EA_INODE_FL) != 0;

            let has_extra = s_inode_size > 128 && inode_slice.len() >= 130;
            let extra_isize = if has_extra {
                u16::from_le_bytes([inode_slice[0x80], inode_slice[0x81]]) as usize
            } else {
                0
            };

            let mut violating_evidence = Vec::new();

            // 1. i_atime
            if !is_ea_inode {
                let atime_lo = u32::from_le_bytes([
                    inode_slice[0x08],
                    inode_slice[0x09],
                    inode_slice[0x0A],
                    inode_slice[0x0B],
                ]);
                let (atime_sec, atime_nsec) = if extra_isize >= 16 && inode_slice.len() >= 0x8C + 4
                {
                    let extra = u32::from_le_bytes([
                        inode_slice[0x8C],
                        inode_slice[0x8D],
                        inode_slice[0x8E],
                        inode_slice[0x8F],
                    ]);
                    ext4_decode_extra_time(atime_lo, extra)
                } else {
                    ((atime_lo as i32) as i64, 0)
                };
                if atime_sec != 0 || atime_nsec != 0 {
                    let is_later = (atime_sec > t_clock_secs)
                        || (atime_sec == t_clock_secs && atime_nsec > t_clock_nanos);
                    if is_later {
                        let atime_str = format_ext4_time(atime_sec, atime_nsec);
                        violating_evidence
                            .push(format!("i_atime {atime_str} > T_clock {t_clock_str}"));
                    }
                }
            }

            // 2. i_ctime
            let ctime_lo = u32::from_le_bytes([
                inode_slice[0x0C],
                inode_slice[0x0D],
                inode_slice[0x0E],
                inode_slice[0x0F],
            ]);
            let (ctime_sec, ctime_nsec) = if extra_isize >= 8 && inode_slice.len() >= 0x84 + 4 {
                let extra = u32::from_le_bytes([
                    inode_slice[0x84],
                    inode_slice[0x85],
                    inode_slice[0x86],
                    inode_slice[0x87],
                ]);
                ext4_decode_extra_time(ctime_lo, extra)
            } else {
                ((ctime_lo as i32) as i64, 0)
            };
            if ctime_sec != 0 || ctime_nsec != 0 {
                let is_later = (ctime_sec > t_clock_secs)
                    || (ctime_sec == t_clock_secs && ctime_nsec > t_clock_nanos);
                if is_later {
                    let ctime_str = format_ext4_time(ctime_sec, ctime_nsec);
                    violating_evidence.push(format!("i_ctime {ctime_str} > T_clock {t_clock_str}"));
                }
            }

            // 3. i_mtime
            let mtime_lo = u32::from_le_bytes([
                inode_slice[0x10],
                inode_slice[0x11],
                inode_slice[0x12],
                inode_slice[0x13],
            ]);
            let (mtime_sec, mtime_nsec) = if extra_isize >= 12 && inode_slice.len() >= 0x88 + 4 {
                let extra = u32::from_le_bytes([
                    inode_slice[0x88],
                    inode_slice[0x89],
                    inode_slice[0x8A],
                    inode_slice[0x8B],
                ]);
                ext4_decode_extra_time(mtime_lo, extra)
            } else {
                ((mtime_lo as i32) as i64, 0)
            };
            if mtime_sec != 0 || mtime_nsec != 0 {
                let is_later = (mtime_sec > t_clock_secs)
                    || (mtime_sec == t_clock_secs && mtime_nsec > t_clock_nanos);
                if is_later {
                    let mtime_str = format_ext4_time(mtime_sec, mtime_nsec);
                    violating_evidence.push(format!("i_mtime {mtime_str} > T_clock {t_clock_str}"));
                }
            }

            // 4. i_crtime (creation time in large inodes)
            if extra_isize >= 20 && inode_slice.len() >= 0x90 + 4 {
                let crtime_lo = u32::from_le_bytes([
                    inode_slice[0x90],
                    inode_slice[0x91],
                    inode_slice[0x92],
                    inode_slice[0x93],
                ]);
                let (crtime_sec, crtime_nsec) =
                    if extra_isize >= 24 && inode_slice.len() >= 0x94 + 4 {
                        let extra = u32::from_le_bytes([
                            inode_slice[0x94],
                            inode_slice[0x95],
                            inode_slice[0x96],
                            inode_slice[0x97],
                        ]);
                        ext4_decode_extra_time(crtime_lo, extra)
                    } else {
                        ((crtime_lo as i32) as i64, 0)
                    };
                if crtime_sec != 0 || crtime_nsec != 0 {
                    let is_later = (crtime_sec > t_clock_secs)
                        || (crtime_sec == t_clock_secs && crtime_nsec > t_clock_nanos);
                    if is_later {
                        let crtime_str = format_ext4_time(crtime_sec, crtime_nsec);
                        violating_evidence
                            .push(format!("i_crtime {crtime_str} > T_clock {t_clock_str}"));
                    }
                }
            }

            // Emit at most one finding per inode path
            if !violating_evidence.is_empty() {
                findings.push(Finding {
                    detector: "D4".into(),
                    channel: "inode".into(),
                    path: format!("{image_display}#inode/{inode_num}"),
                    visibility: Visibility::AgentVisible,
                    severity: Severity::Gate,
                    confidence: 1.0,
                    hunk: None,
                    evidence: violating_evidence,
                });
            }
        }
    }

    Ok(findings)
}

/// Scan an ext4 image in memory against `T_clock`.
pub fn scan_ext4_slice(image_display: &str, data: &[u8], t_clock: OffsetDateTime) -> Vec<Finding> {
    match parse_ext4(image_display, data, t_clock) {
        Ok(findings) => findings,
        Err(e) => vec![Finding {
            detector: "D4".into(),
            channel: "image_malformed".into(),
            path: image_display.to_string(),
            visibility: Visibility::AgentVisible,
            severity: Severity::Info,
            confidence: 0.0,
            hunk: None,
            evidence: vec![format!("malformed ext4 image: {}", e.0)],
        }],
    }
}

/// Scan an ext4 image file from disk against `T_clock`.
pub fn scan_ext4_image(image_path: &Path, t_clock: OffsetDateTime) -> Vec<Finding> {
    let display = image_path.display().to_string();
    let data = match std::fs::read(image_path) {
        Ok(d) => d,
        Err(e) => {
            return vec![Finding {
                detector: "D4".into(),
                channel: "image_malformed".into(),
                path: display,
                visibility: Visibility::AgentVisible,
                severity: Severity::Info,
                confidence: 0.0,
                hunk: None,
                evidence: vec![format!("failed to read image file: {e}")],
            }];
        }
    };
    scan_ext4_slice(&display, &data, t_clock)
}
