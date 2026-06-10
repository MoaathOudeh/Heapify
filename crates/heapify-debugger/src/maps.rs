use anyhow::{bail, Context, Result};
use nix::unistd::Pid;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMapping {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: Option<String>,
}

pub fn parse_maps_line(line: &str) -> Result<MemoryMapping> {
    let mut fields = line.split_whitespace();

    let range = fields.next().context("missing address range")?;
    let permissions = fields.next().context("missing permissions")?.to_string();
    let offset = parse_hex_u64(fields.next().context("missing offset")?)?;
    let dev = fields.next().context("missing device")?.to_string();
    let inode = fields
        .next()
        .context("missing inode")?
        .parse()
        .context("invalid inode")?;

    let (start, end) = parse_address_range(range)?;
    let pathname = fields.collect::<Vec<_>>().join(" ");
    let pathname = if pathname.is_empty() {
        None
    } else {
        Some(pathname)
    };

    Ok(MemoryMapping {
        start,
        end,
        permissions,
        offset,
        dev,
        inode,
        pathname,
    })
}

pub fn read_process_maps(pid: Pid) -> Result<Vec<MemoryMapping>> {
    let path = format!("/proc/{}/maps", pid.as_raw());
    let maps = std::fs::read_to_string(&path).with_context(|| format!("failed to read {path}"))?;

    maps.lines()
        .map(parse_maps_line)
        .collect::<Result<Vec<_>>>()
}

pub fn find_heap_mapping(pid: Pid) -> Result<Option<MemoryMapping>> {
    Ok(read_process_maps(pid)?
        .into_iter()
        .find(|mapping| mapping.pathname.as_deref() == Some("[heap]")))
}

pub fn find_libc_mapping(pid: Pid) -> Result<Option<MemoryMapping>> {
    Ok(read_process_maps(pid)?
        .into_iter()
        .find(mapping_matches_libc_path))
}

pub fn find_executable_mapping(pid: Pid, program_path: &str) -> Result<Option<MemoryMapping>> {
    let canonical_program = std::fs::canonicalize(program_path)
        .with_context(|| format!("failed to canonicalize program path: {program_path}"))?;

    Ok(read_process_maps(pid)?
        .into_iter()
        .find(|mapping| mapping_matches_executable_path(mapping, canonical_program.as_path())))
}

pub fn mapping_load_base(mapping: &MemoryMapping) -> Result<u64> {
    mapping.start.checked_sub(mapping.offset).with_context(|| {
        format!(
            "mapping start 0x{:x} is below offset 0x{:x}",
            mapping.start, mapping.offset
        )
    })
}

fn mapping_matches_libc_path(mapping: &MemoryMapping) -> bool {
    if !mapping.permissions.contains('x') {
        return false;
    }

    let Some(pathname) = &mapping.pathname else {
        return false;
    };

    pathname.contains("libc.so") || pathname.ends_with("/libc.so.6") || pathname.contains("libc-")
}

fn mapping_matches_executable_path(mapping: &MemoryMapping, canonical_program: &Path) -> bool {
    if !mapping.permissions.contains('x') {
        return false;
    }

    let Some(pathname) = &mapping.pathname else {
        return false;
    };

    if pathname == canonical_program.to_string_lossy().as_ref() {
        return true;
    }

    std::fs::canonicalize(pathname)
        .map(|canonical_mapping| canonical_mapping == canonical_program)
        .unwrap_or(false)
}

fn parse_address_range(range: &str) -> Result<(u64, u64)> {
    let Some((start, end)) = range.split_once('-') else {
        bail!("invalid address range: {range}");
    };

    if start.is_empty() || end.is_empty() {
        bail!("invalid address range: {range}");
    }

    Ok((parse_hex_u64(start)?, parse_hex_u64(end)?))
}

fn parse_hex_u64(value: &str) -> Result<u64> {
    u64::from_str_radix(value, 16).with_context(|| format!("invalid hex value: {value}"))
}

#[cfg(test)]
mod tests {
    use super::{
        mapping_load_base, mapping_matches_executable_path, mapping_matches_libc_path,
        parse_maps_line, MemoryMapping,
    };
    use std::path::Path;

    #[test]
    fn parses_heap_mapping() {
        let mapping = parse_maps_line(
            "555555559000-55555557a000 rw-p 00000000 00:00 0                          [heap]",
        )
        .unwrap();

        assert_eq!(mapping.start, 0x555555559000);
        assert_eq!(mapping.end, 0x55555557a000);
        assert_eq!(mapping.permissions, "rw-p");
        assert_eq!(mapping.offset, 0);
        assert_eq!(mapping.dev, "00:00");
        assert_eq!(mapping.inode, 0);
        assert_eq!(mapping.pathname.as_deref(), Some("[heap]"));
    }

    #[test]
    fn parses_file_pathname() {
        let mapping = parse_maps_line(
            "7ffff7dd5000-7ffff7dfb000 r--p 00000000 08:20 12345 /usr/lib/x86_64-linux-gnu/libc.so.6",
        )
        .unwrap();

        assert_eq!(mapping.start, 0x7ffff7dd5000);
        assert_eq!(mapping.end, 0x7ffff7dfb000);
        assert_eq!(mapping.permissions, "r--p");
        assert_eq!(mapping.offset, 0);
        assert_eq!(mapping.dev, "08:20");
        assert_eq!(mapping.inode, 12345);
        assert_eq!(
            mapping.pathname.as_deref(),
            Some("/usr/lib/x86_64-linux-gnu/libc.so.6")
        );
    }

    #[test]
    fn parses_mapping_without_pathname() {
        let mapping = parse_maps_line("7ffff7ff9000-7ffff7ffd000 rw-p 00000000 00:00 0").unwrap();

        assert_eq!(mapping.start, 0x7ffff7ff9000);
        assert_eq!(mapping.end, 0x7ffff7ffd000);
        assert_eq!(mapping.permissions, "rw-p");
        assert_eq!(mapping.offset, 0);
        assert_eq!(mapping.dev, "00:00");
        assert_eq!(mapping.inode, 0);
        assert_eq!(mapping.pathname, None);
    }

    #[test]
    fn invalid_address_range_returns_error() {
        let result = parse_maps_line("not-a-range rw-p 00000000 00:00 0 [heap]");

        assert!(result.is_err());
    }

    #[test]
    fn executable_mapping_matches_canonical_path_string() {
        let mapping = MemoryMapping {
            start: 0x555555555000,
            end: 0x555555556000,
            permissions: "r-xp".to_string(),
            offset: 0x1000,
            dev: "08:20".to_string(),
            inode: 12345,
            pathname: Some("/tmp/heapify-target".to_string()),
        };

        assert!(mapping_matches_executable_path(
            &mapping,
            Path::new("/tmp/heapify-target")
        ));
    }

    #[test]
    fn executable_mapping_rejects_non_executable_permissions() {
        let mapping = MemoryMapping {
            start: 0x555555555000,
            end: 0x555555556000,
            permissions: "r--p".to_string(),
            offset: 0,
            dev: "08:20".to_string(),
            inode: 12345,
            pathname: Some("/tmp/heapify-target".to_string()),
        };

        assert!(!mapping_matches_executable_path(
            &mapping,
            Path::new("/tmp/heapify-target")
        ));
    }

    #[test]
    fn libc_mapping_matches_common_glibc_paths() {
        let mapping = MemoryMapping {
            start: 0x7ffff7dd5000,
            end: 0x7ffff7dfb000,
            permissions: "r-xp".to_string(),
            offset: 0x26000,
            dev: "08:20".to_string(),
            inode: 12345,
            pathname: Some("/usr/lib/x86_64-linux-gnu/libc.so.6".to_string()),
        };

        assert!(mapping_matches_libc_path(&mapping));
    }

    #[test]
    fn libc_mapping_rejects_non_executable_permissions() {
        let mapping = MemoryMapping {
            start: 0x7ffff7dd5000,
            end: 0x7ffff7dfb000,
            permissions: "r--p".to_string(),
            offset: 0,
            dev: "08:20".to_string(),
            inode: 12345,
            pathname: Some("/usr/lib/x86_64-linux-gnu/libc.so.6".to_string()),
        };

        assert!(!mapping_matches_libc_path(&mapping));
    }

    #[test]
    fn mapping_load_base_subtracts_offset() {
        let mapping = MemoryMapping {
            start: 0x7ffff7dd5000,
            end: 0x7ffff7dfb000,
            permissions: "r-xp".to_string(),
            offset: 0x26000,
            dev: "08:20".to_string(),
            inode: 12345,
            pathname: Some("/usr/lib/x86_64-linux-gnu/libc.so.6".to_string()),
        };

        assert_eq!(mapping_load_base(&mapping).unwrap(), 0x7ffff7daf000);
    }

    #[test]
    fn mapping_load_base_errors_on_underflow() {
        let mapping = MemoryMapping {
            start: 0x1000,
            end: 0x2000,
            permissions: "r-xp".to_string(),
            offset: 0x3000,
            dev: "08:20".to_string(),
            inode: 12345,
            pathname: Some("/tmp/target".to_string()),
        };

        assert!(mapping_load_base(&mapping).is_err());
    }
}
