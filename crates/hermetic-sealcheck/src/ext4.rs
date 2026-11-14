//! Ext4 filesystem image verification for D4 timestamps (TR-SC-7, TR-SEAL-7).
//!
//! Checks that no inode or superblock timestamp in an ext4 image is later than `T_clock`.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use time::OffsetDateTime;

use crate::scan::{Finding, Severity, Visibility};

const SUPERBLOCK_OFFSET: usize = 1024;
const SUPERBLOCK_SIZE: usize = 1024;
pub const MAX_IMAGE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_BLOCK_BYTES: usize = 64 * 1024;
const MAX_METADATA_READ_BYTES: u64 = MAX_IMAGE_BYTES;
const MAX_EXTENT_DEPTH: u16 = 5;
const MAX_EXTENT_NODES: u64 = 1_000_000;
const MAX_IMAGE_INODES: u64 = 1_000_000;
const MAX_IMAGE_FINDINGS: usize = 100_000;
const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_BG_INODE_UNINIT: u16 = 0x0001;
const EXT4_EA_INODE_FL: u32 = 0x0020_0000;

const EXT4_FEATURE_INCOMPAT_COMPACT_DIR: u32 = 0x0001;
const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
const EXT4_FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const EXT4_FEATURE_INCOMPAT_META_BG: u32 = 0x0010;
const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
const EXT4_FEATURE_INCOMPAT_MMP: u32 = 0x0100;
const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
const EXT4_FEATURE_INCOMPAT_EA_INODE: u32 = 0x0400;
const EXT4_FEATURE_INCOMPAT_DIRDATA: u32 = 0x1000;
const EXT4_FEATURE_INCOMPAT_CSUM_SEED: u32 = 0x2000;
const EXT4_FEATURE_INCOMPAT_LARGEDIR: u32 = 0x4000;
const EXT4_FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000;
const EXT4_FEATURE_INCOMPAT_ENCRYPT: u32 = 0x10000;

const SUPPORTED_INCOMPAT: u32 = EXT4_FEATURE_INCOMPAT_COMPACT_DIR
    | EXT4_FEATURE_INCOMPAT_FILETYPE
    | EXT4_FEATURE_INCOMPAT_RECOVER
    | EXT4_FEATURE_INCOMPAT_EXTENTS
    | EXT4_FEATURE_INCOMPAT_64BIT
    | EXT4_FEATURE_INCOMPAT_MMP
    | EXT4_FEATURE_INCOMPAT_FLEX_BG
    | EXT4_FEATURE_INCOMPAT_EA_INODE
    | EXT4_FEATURE_INCOMPAT_DIRDATA
    | EXT4_FEATURE_INCOMPAT_CSUM_SEED
    | EXT4_FEATURE_INCOMPAT_LARGEDIR
    | EXT4_FEATURE_INCOMPAT_INLINE_DATA
    | EXT4_FEATURE_INCOMPAT_ENCRYPT;

#[derive(Debug, thiserror::Error)]
pub enum Ext4Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed ext4 image: {0}")]
    Malformed(String),
    #[error("unsupported ext4 feature: {0}")]
    Unsupported(String),
}

/// Decode extra time bits using the kernel's `ext4_decode_extra_time` algorithm.
///
/// The lower 2 bits of `extra` extend the 32-bit signed seconds field by 2 bits.
/// The upper 30 bits of `extra` store the nanoseconds.
fn ext4_decode_extra_time(base: u32, extra: u32) -> Result<(i64, u32), Ext4Error> {
    let mut sec = (base as i32) as i64;
    let epoch = (extra & 3) as u64;
    if epoch != 0 {
        sec = sec
            .checked_add((epoch << 32) as i64)
            .ok_or_else(|| malformed("inode timestamp overflow"))?;
    }
    let nsec = (extra & 0xFFFF_FFFC) >> 2;
    if nsec >= 1_000_000_000 {
        return Err(Ext4Error::Malformed(
            "invalid inode timestamp nanoseconds".into(),
        ));
    }
    Ok((sec, nsec))
}

fn malformed(message: &str) -> Ext4Error {
    Ext4Error::Malformed(message.into())
}

fn bytes<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], Ext4Error> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| malformed("field offset overflow"))?;
    data.get(offset..end)
        .and_then(|field| field.try_into().ok())
        .ok_or_else(|| malformed("field out of bounds"))
}

fn decode_sb_time(sb: &[u8], lo_off: usize, hi_off: usize) -> Result<i64, Ext4Error> {
    let lo = u32::from_le_bytes(bytes(sb, lo_off)?);
    let hi = sb
        .get(hi_off)
        .ok_or_else(|| malformed("timestamp out of bounds"))?;
    Ok((((u64::from(*hi)) << 32) | u64::from(lo)) as i64)
}

trait Positioned {
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> Result<(), Ext4Error>;
}

impl Positioned for File {
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> Result<(), Ext4Error> {
        self.read_exact_at(buffer, offset)?;
        Ok(())
    }
}

impl Positioned for &[u8] {
    fn read_at(&self, buffer: &mut [u8], offset: u64) -> Result<(), Ext4Error> {
        let start = usize::try_from(offset).map_err(|_| malformed("read offset overflow"))?;
        let end = start
            .checked_add(buffer.len())
            .ok_or_else(|| malformed("read end overflow"))?;
        buffer.copy_from_slice(
            self.get(start..end)
                .ok_or_else(|| malformed("truncated image"))?,
        );
        Ok(())
    }
}

struct Image<R> {
    source: R,
    len: u64,
    read_bytes: u64,
    extent_nodes: u64,
}

impl<R: Positioned> Image<R> {
    fn new(source: R, len: u64) -> Result<Self, Ext4Error> {
        if len > MAX_IMAGE_BYTES {
            return Err(malformed("image byte cap exceeded"));
        }
        Ok(Self {
            source,
            len,
            read_bytes: 0,
            extent_nodes: 0,
        })
    }

    fn range(&self, offset: u64, len: u64) -> Result<(), Ext4Error> {
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(malformed("image range out of bounds"));
        }
        Ok(())
    }

    fn read(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, Ext4Error> {
        if len > MAX_BLOCK_BYTES {
            return Err(malformed("image read size cap exceeded"));
        }
        self.range(offset, len as u64)?;
        self.read_bytes = self
            .read_bytes
            .checked_add(len as u64)
            .filter(|total| *total <= MAX_METADATA_READ_BYTES)
            .ok_or_else(|| malformed("image metadata read cap exceeded"))?;
        let mut buffer = vec![0; len];
        self.source.read_at(&mut buffer, offset)?;
        Ok(buffer)
    }
}

// Validate physical extent ranges without reading file contents. Sparse holes
// require no reads. Index depth decreases on every edge; nodes and I/O share
// image-wide budgets so repeated or cyclic hostile references cannot run away.
fn check_extents<R: Positioned>(
    image: &mut Image<R>,
    node: &[u8],
    block_size: u64,
    total_blocks: u64,
    expected_depth: Option<u16>,
) -> Result<(), Ext4Error> {
    let magic = u16::from_le_bytes(bytes(node, 0)?);
    let entries = u16::from_le_bytes(bytes(node, 2)?);
    let capacity = u16::from_le_bytes(bytes(node, 4)?);
    let depth = u16::from_le_bytes(bytes(node, 6)?);
    if magic != 0xf30a
        || depth > MAX_EXTENT_DEPTH
        || expected_depth.is_some_and(|expected| expected != depth)
        || entries > capacity
        || usize::from(capacity) > node.len().saturating_sub(12) / 12
    {
        return Err(malformed("invalid extent header"));
    }
    image.extent_nodes = image
        .extent_nodes
        .checked_add(1)
        .filter(|count| *count <= MAX_EXTENT_NODES)
        .ok_or_else(|| malformed("extent node cap exceeded"))?;
    let mut previous_end = 0u64;
    for entry in node
        .get(12..)
        .ok_or_else(|| malformed("invalid extent node"))?
        .as_chunks::<12>()
        .0
        .iter()
        .take(usize::from(entries))
    {
        let logical = u64::from(u32::from_le_bytes(bytes(entry, 0)?));
        if logical < previous_end {
            return Err(malformed("unordered extents"));
        }
        if depth == 0 {
            let raw_len = u16::from_le_bytes(bytes(entry, 4)?);
            let len = u64::from(if raw_len > 32768 {
                raw_len - 32768
            } else {
                raw_len
            });
            let start = (u64::from(u16::from_le_bytes(bytes(entry, 6)?)) << 32)
                | u64::from(u32::from_le_bytes(bytes(entry, 8)?));
            if len == 0 || start == 0 || start.checked_add(len).is_none_or(|end| end > total_blocks)
            {
                return Err(malformed("extent past end of image"));
            }
            previous_end = logical
                .checked_add(len)
                .ok_or_else(|| malformed("extent overflow"))?;
        } else {
            let start = (u64::from(u16::from_le_bytes(bytes(entry, 8)?)) << 32)
                | u64::from(u32::from_le_bytes(bytes(entry, 4)?));
            if start == 0 || start >= total_blocks {
                return Err(malformed("extent index past end of image"));
            }
            let offset = start
                .checked_mul(block_size)
                .ok_or_else(|| malformed("extent offset overflow"))?;
            let child = image.read(offset, block_size as usize)?;
            check_extents(
                image,
                &child,
                block_size,
                total_blocks,
                depth.checked_sub(1),
            )?;
            previous_end = logical
                .checked_add(1)
                .ok_or_else(|| malformed("extent overflow"))?;
        }
    }
    Ok(())
}

fn format_ext4_time(sec: i64, nsec: u32) -> String {
    let total_nanos = (sec as i128)
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nsec as i128));
    match total_nanos.and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()) {
        Some(dt) => dt
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| dt.to_string()),
        None => format!("{sec}s"),
    }
}

fn parse_ext4<R: Positioned>(
    image_display: &str,
    image: &mut Image<R>,
    t_clock: OffsetDateTime,
) -> Result<Vec<Finding>, Ext4Error> {
    if image.len < (SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE) as u64 {
        return Err(Ext4Error::Malformed(format!(
            "image too small for superblock ({} < 2048 bytes)",
            image.len
        )));
    }

    let sb_data = image.read(SUPERBLOCK_OFFSET as u64, SUPERBLOCK_SIZE)?;
    let sb = sb_data.as_slice();

    // Magic check
    let magic = u16::from_le_bytes(bytes(sb, 0x38)?);
    if magic != EXT4_MAGIC {
        return Err(Ext4Error::Malformed(format!(
            "bad magic 0x{magic:04x}, expected 0xef53"
        )));
    }

    // Incompatible feature checks
    let s_feature_incompat = u32::from_le_bytes(bytes(sb, 0x60)?);
    if (s_feature_incompat & EXT4_FEATURE_INCOMPAT_META_BG) != 0 {
        return Err(Ext4Error::Unsupported("meta_bg".into()));
    }
    if (s_feature_incompat & EXT4_FEATURE_INCOMPAT_JOURNAL_DEV) != 0 {
        return Err(Ext4Error::Unsupported("journal_dev".into()));
    }
    if (s_feature_incompat & EXT4_FEATURE_INCOMPAT_RECOVER) != 0 {
        return Err(Ext4Error::Unsupported("journal recovery required".into()));
    }
    let unsupported = s_feature_incompat & !SUPPORTED_INCOMPAT;
    if unsupported != 0 {
        return Err(Ext4Error::Unsupported(format!(
            "unsupported incompat feature flags 0x{unsupported:08x}"
        )));
    }

    // Block size: 1024 << s_log_block_size
    let s_log_block_size = u32::from_le_bytes(bytes(sb, 0x18)?);
    if s_log_block_size > 6 {
        return Err(Ext4Error::Malformed(format!(
            "invalid block size log {s_log_block_size}"
        )));
    }
    let block_size = match 1024u64.checked_shl(s_log_block_size) {
        Some(sz) => sz,
        None => return Err(Ext4Error::Malformed("block size overflow".into())),
    };

    // Inode size
    let s_inode_size = u16::from_le_bytes(bytes(sb, 0x58)?) as usize;
    if s_inode_size < 128 || !s_inode_size.is_power_of_two() || (s_inode_size as u64) > block_size {
        return Err(Ext4Error::Malformed(format!(
            "invalid inode size {s_inode_size}"
        )));
    }

    // Inodes per group and total inodes
    let s_inodes_per_group = u32::from_le_bytes(bytes(sb, 0x28)?) as u64;
    let s_inodes_count = u32::from_le_bytes(bytes(sb, 0x00)?) as u64;
    if s_inodes_count > MAX_IMAGE_INODES {
        return Err(Ext4Error::Malformed("image inode cap exceeded".into()));
    }
    if s_inodes_per_group == 0 || s_inodes_count == 0 {
        return Err(Ext4Error::Malformed(
            "inodes per group or total inodes is zero".into(),
        ));
    }
    if s_inodes_per_group > s_inodes_count {
        return Err(Ext4Error::Malformed(
            "inodes per group exceeds total inodes".into(),
        ));
    }
    let max_inodes_in_bitmap = match block_size.checked_mul(8) {
        Some(m) => m,
        None => return Err(Ext4Error::Malformed("bitmap capacity overflow".into())),
    };
    if s_inodes_per_group > max_inodes_in_bitmap {
        return Err(Ext4Error::Malformed(format!(
            "huge inodes per group {s_inodes_per_group} exceeds bitmap capacity"
        )));
    }
    let itable_group_bytes = match s_inodes_per_group.checked_mul(s_inode_size as u64) {
        Some(b) => b,
        None => return Err(Ext4Error::Malformed("inode table size overflow".into())),
    };
    if itable_group_bytes > image.len {
        return Err(Ext4Error::Malformed(
            "inodes per group table exceeds image size".into(),
        ));
    }

    // 64-bit feature and descriptor size
    let is_64bit = (s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0;
    let s_desc_size = u16::from_le_bytes(bytes(sb, 0xFE)?) as usize;
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
        return Err(Ext4Error::Malformed(format!(
            "invalid descriptor size {desc_size}"
        )));
    }
    if is_64bit && desc_size < 64 {
        return Err(Ext4Error::Malformed(format!(
            "64-bit filesystem descriptor size {desc_size} < 64"
        )));
    }

    // Blocks per group and total blocks
    let s_blocks_per_group = u32::from_le_bytes(bytes(sb, 0x20)?) as u64;
    if s_blocks_per_group == 0 {
        return Err(Ext4Error::Malformed("blocks per group is zero".into()));
    }
    let s_blocks_count_lo = u32::from_le_bytes(bytes(sb, 0x04)?) as u64;
    let s_blocks_count_hi = if is_64bit {
        u32::from_le_bytes(bytes(sb, 0x150)?) as u64
    } else {
        0
    };
    let total_blocks = s_blocks_count_lo | (s_blocks_count_hi << 32);
    if total_blocks == 0 {
        return Err(Ext4Error::Malformed("total blocks is zero".into()));
    }

    // Group count calculation
    let s_first_data_block = u32::from_le_bytes(bytes(sb, 0x14)?) as u64;
    let remaining_blocks = match total_blocks.checked_sub(s_first_data_block) {
        Some(b) => b,
        None => {
            return Err(Ext4Error::Malformed(
                "first data block exceeds total blocks".into(),
            ))
        }
    };
    let group_count = remaining_blocks.div_ceil(s_blocks_per_group);
    let group_count_from_inodes = s_inodes_count.div_ceil(s_inodes_per_group);
    if group_count == 0 || group_count_from_inodes == 0 {
        return Err(Ext4Error::Malformed("group count is zero".into()));
    }
    if group_count != group_count_from_inodes {
        return Err(Ext4Error::Malformed(format!(
            "group count mismatch: {group_count} from blocks, {group_count_from_inodes} from inodes"
        )));
    }

    // Check bounds: descriptor table and total blocks against image size
    let gdt_block = match s_first_data_block.checked_add(1) {
        Some(b) => b,
        None => return Err(Ext4Error::Malformed("gdt block overflow".into())),
    };
    let gdt_offset = match gdt_block.checked_mul(block_size) {
        Some(off) => off,
        None => return Err(Ext4Error::Malformed("gdt offset overflow".into())),
    };
    let gdt_size = match group_count.checked_mul(desc_size as u64) {
        Some(sz) => sz,
        None => return Err(Ext4Error::Malformed("gdt size overflow".into())),
    };
    let gdt_end = match gdt_offset.checked_add(gdt_size) {
        Some(end) => end,
        None => return Err(Ext4Error::Malformed("gdt end overflow".into())),
    };
    if gdt_end > image.len {
        return Err(Ext4Error::Malformed(
            "descriptor table past the end of image".into(),
        ));
    }
    let total_image_bytes = match total_blocks.checked_mul(block_size) {
        Some(b) => b,
        None => return Err(Ext4Error::Malformed("total blocks bytes overflow".into())),
    };
    if total_image_bytes > image.len {
        return Err(Ext4Error::Malformed("group count past the file".into()));
    }
    // No metadata pointer may use trailing bytes outside the filesystem.
    image.len = total_image_bytes;

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
        let sec = decode_sb_time(sb, lo_off, hi_off)?;
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
        let g_desc_off = match g.checked_mul(desc_size as u64) {
            Some(off) => off,
            None => {
                return Err(Ext4Error::Malformed(
                    "group descriptor offset overflow".into(),
                ))
            }
        };
        let gd_offset_u64 = match gdt_offset.checked_add(g_desc_off) {
            Some(off) => off,
            None => {
                return Err(Ext4Error::Malformed(
                    "group descriptor offset overflow".into(),
                ))
            }
        };
        let gd_data = image.read(gd_offset_u64, desc_size)?;
        let gd = gd_data.as_slice();

        let bg_flags = u16::from_le_bytes(bytes(gd, 0x12)?);
        if (bg_flags & EXT4_BG_INODE_UNINIT) != 0 {
            // Skip uninitialized inode table
            continue;
        }

        let bg_inode_bitmap_lo = u32::from_le_bytes(bytes(gd, 0x04)?) as u64;
        let bg_inode_bitmap_hi = if is_64bit && desc_size >= 64 {
            u32::from_le_bytes(bytes(gd, 0x24)?) as u64
        } else {
            0
        };
        let inode_bitmap_block = bg_inode_bitmap_lo | (bg_inode_bitmap_hi << 32);

        let bg_inode_table_lo = u32::from_le_bytes(bytes(gd, 0x08)?) as u64;
        let bg_inode_table_hi = if is_64bit && desc_size >= 64 {
            u32::from_le_bytes(bytes(gd, 0x28)?) as u64
        } else {
            0
        };
        let inode_table_block = bg_inode_table_lo | (bg_inode_table_hi << 32);

        let bitmap_offset_u64 = match inode_bitmap_block.checked_mul(block_size) {
            Some(off) => off,
            None => return Err(Ext4Error::Malformed("bitmap offset overflow".into())),
        };
        let bitmap_slice = image.read(bitmap_offset_u64, block_size as usize)?;
        let itable_offset = inode_table_block
            .checked_mul(block_size)
            .ok_or_else(|| malformed("inode table offset overflow"))?;
        image.range(itable_offset, itable_group_bytes)?;
        let mut inode_block = Vec::new();
        let mut inode_block_offset = None;

        for i in 0..s_inodes_per_group {
            let inode_num = match g
                .checked_mul(s_inodes_per_group)
                .and_then(|x| x.checked_add(i))
                .and_then(|x| x.checked_add(1))
            {
                Some(num) => num,
                None => return Err(Ext4Error::Malformed("inode number overflow".into())),
            };
            if inode_num > s_inodes_count {
                break;
            }

            let byte_idx = (i / 8) as usize;
            let bit_idx = (i % 8) as u8;
            if byte_idx >= bitmap_slice.len() {
                return Err(Ext4Error::Malformed(
                    "inode bitmap index out of bounds".into(),
                ));
            }

            if (*bitmap_slice
                .get(byte_idx)
                .ok_or_else(|| malformed("inode bitmap index out of bounds"))?
                & (1 << bit_idx))
                == 0
            {
                // Inode not in use
                continue;
            }

            let inode_offset = i
                .checked_mul(s_inode_size as u64)
                .and_then(|off| itable_offset.checked_add(off))
                .ok_or_else(|| malformed("inode offset overflow"))?;
            let block_offset = inode_offset
                .checked_sub(inode_offset % block_size)
                .ok_or_else(|| malformed("inode block offset overflow"))?;
            if inode_block_offset != Some(block_offset) {
                inode_block = image.read(block_offset, block_size as usize)?;
                inode_block_offset = Some(block_offset);
            }
            let start = (inode_offset % block_size) as usize;
            let end = start
                .checked_add(s_inode_size)
                .ok_or_else(|| malformed("inode slice overflow"))?;
            let inode_slice = inode_block
                .get(start..end)
                .ok_or_else(|| malformed("inode slice out of bounds"))?;

            // The allocation bitmap is authoritative. An allocated inode with a
            // deletion time is inconsistent, never an excuse to skip its times.
            let dtime = u32::from_le_bytes(bytes(inode_slice, 0x14)?);
            if dtime != 0 {
                return Err(Ext4Error::Malformed(
                    "allocated inode has a deletion time".into(),
                ));
            }

            let flags = u32::from_le_bytes(bytes(inode_slice, 0x20)?);
            if flags & 0x0008_0000 != 0 {
                let root = inode_slice
                    .get(0x28..0x64)
                    .ok_or_else(|| malformed("extent root out of bounds"))?;
                check_extents(image, root, block_size, total_blocks, None)?;
            }
            let is_ea_inode = (flags & EXT4_EA_INODE_FL) != 0;

            let has_extra = s_inode_size > 128 && inode_slice.len() >= 130;
            let extra_isize = if has_extra {
                u16::from_le_bytes(bytes(inode_slice, 0x80)?) as usize
            } else {
                0
            };
            if extra_isize > s_inode_size.saturating_sub(128) || extra_isize % 4 != 0 {
                return Err(Ext4Error::Malformed("invalid inode extra size".into()));
            }

            let mut violating_evidence = Vec::new();

            // 1. i_atime
            if !is_ea_inode {
                let atime_lo = u32::from_le_bytes(bytes(inode_slice, 0x08)?);
                let (atime_sec, atime_nsec) = if extra_isize >= 16 && inode_slice.len() >= 0x8C + 4
                {
                    let extra = u32::from_le_bytes(bytes(inode_slice, 0x8C)?);
                    ext4_decode_extra_time(atime_lo, extra)?
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
            let ctime_lo = u32::from_le_bytes(bytes(inode_slice, 0x0C)?);
            let (ctime_sec, ctime_nsec) = if extra_isize >= 8 && inode_slice.len() >= 0x84 + 4 {
                let extra = u32::from_le_bytes(bytes(inode_slice, 0x84)?);
                ext4_decode_extra_time(ctime_lo, extra)?
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
            let mtime_lo = u32::from_le_bytes(bytes(inode_slice, 0x10)?);
            let (mtime_sec, mtime_nsec) = if extra_isize >= 12 && inode_slice.len() >= 0x88 + 4 {
                let extra = u32::from_le_bytes(bytes(inode_slice, 0x88)?);
                ext4_decode_extra_time(mtime_lo, extra)?
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
                let crtime_lo = u32::from_le_bytes(bytes(inode_slice, 0x90)?);
                let (crtime_sec, crtime_nsec) =
                    if extra_isize >= 24 && inode_slice.len() >= 0x94 + 4 {
                        let extra = u32::from_le_bytes(bytes(inode_slice, 0x94)?);
                        ext4_decode_extra_time(crtime_lo, extra)?
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
                if findings.len() >= MAX_IMAGE_FINDINGS {
                    return Err(Ext4Error::Malformed("image finding cap exceeded".into()));
                }
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
pub fn scan_ext4_slice(
    image_display: &str,
    data: &[u8],
    t_clock: OffsetDateTime,
) -> Result<Vec<Finding>, Ext4Error> {
    let mut image = Image::new(data, data.len() as u64)?;
    parse_ext4(image_display, &mut image, t_clock)
}

/// Stable evidence label, including when the image arrives on an inherited descriptor.
pub fn image_display(image_path: &Path) -> String {
    if image_path.parent() == Some(Path::new("/proc/self/fd")) {
        "<image>".into()
    } else {
        image_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    }
}

/// Scan a regular image path or an explicitly inherited image descriptor.
pub fn scan_ext4_image(
    image_path: &Path,
    t_clock: OffsetDateTime,
) -> Result<Vec<Finding>, Ext4Error> {
    let display = image_display(image_path);
    let file = crate::safe_fs::open_regular(image_path)?;
    let length = file.metadata()?.len();
    let mut image = Image::new(file, length)?;
    let findings = parse_ext4(&display, &mut image, t_clock)?;
    if image.source.metadata()?.len() != length {
        return Err(malformed("image size changed during scan"));
    }
    Ok(findings)
}
