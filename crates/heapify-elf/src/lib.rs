use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSymbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfFileType {
    Executable,
    PositionIndependentExecutable,
    SharedObject,
    Other,
}

pub fn elf_file_type(path: &str) -> Result<ElfFileType> {
    let data = std::fs::read(path).with_context(|| format!("failed to read ELF file: {path}"))?;
    elf_file_type_from_bytes(&data).with_context(|| format!("failed to read ELF type: {path}"))
}

pub fn is_pie(path: &str) -> Result<bool> {
    Ok(elf_file_type(path)? == ElfFileType::PositionIndependentExecutable)
}

pub fn entry_point(path: &str) -> Result<u64> {
    let data = std::fs::read(path).with_context(|| format!("failed to read ELF file: {path}"))?;
    let file = object::File::parse(data.as_slice())
        .with_context(|| format!("failed to parse ELF file: {path}"))?;

    Ok(file.entry())
}

pub fn find_symbol(path: &str, name: &str) -> Result<Option<u64>> {
    let data = std::fs::read(path).with_context(|| format!("failed to read ELF file: {path}"))?;
    let file = object::File::parse(data.as_slice())
        .with_context(|| format!("failed to parse ELF file: {path}"))?;

    for symbol in file.symbols() {
        if symbol.name().ok() == Some(name) {
            let addr = symbol.address();
            if addr != 0 {
                return Ok(Some(addr));
            }
        }
    }

    for symbol in file.dynamic_symbols() {
        if symbol.name().ok() == Some(name) {
            let addr = symbol.address();
            if addr != 0 {
                return Ok(Some(addr));
            }
        }
    }

    Ok(None)
}

pub fn list_symbols(path: &str) -> Result<Vec<ElfSymbol>> {
    let data = std::fs::read(path).with_context(|| format!("failed to read ELF file: {path}"))?;
    let file = object::File::parse(data.as_slice())
        .with_context(|| format!("failed to parse ELF file: {path}"))?;
    let mut symbols = Vec::new();

    for symbol in file.symbols() {
        push_symbol(&mut symbols, symbol);
    }
    for symbol in file.dynamic_symbols() {
        push_symbol(&mut symbols, symbol);
    }

    sort_and_dedup_symbols(&mut symbols);

    Ok(symbols)
}

fn sort_and_dedup_symbols(symbols: &mut Vec<ElfSymbol>) {
    symbols.sort_by(|left, right| {
        left.addr
            .cmp(&right.addr)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.size.cmp(&right.size))
    });
    symbols.dedup_by(|left, right| left.name == right.name && left.addr == right.addr);
}

fn push_symbol(symbols: &mut Vec<ElfSymbol>, symbol: object::Symbol<'_, '_>) {
    let Ok(name) = symbol.name() else {
        return;
    };
    if name.is_empty() || symbol.address() == 0 {
        return;
    }

    symbols.push(ElfSymbol {
        name: name.to_string(),
        addr: symbol.address(),
        size: symbol.size(),
    });
}

pub fn find_symbol_by_prefix(path: &str, prefix: &str) -> Result<Option<(String, u64)>> {
    let data = std::fs::read(path).with_context(|| format!("failed to read ELF file: {path}"))?;
    let file = object::File::parse(data.as_slice())
        .with_context(|| format!("failed to parse ELF file: {path}"))?;

    for symbol in file.symbols() {
        if let Some(found) = matching_nonzero_symbol(symbol.name().ok(), symbol.address(), prefix) {
            return Ok(Some(found));
        }
    }

    for symbol in file.dynamic_symbols() {
        if let Some(found) = matching_nonzero_symbol(symbol.name().ok(), symbol.address(), prefix) {
            return Ok(Some(found));
        }
    }

    find_plt_symbol_by_prefix(&file, prefix)
}

fn matching_nonzero_symbol(name: Option<&str>, addr: u64, prefix: &str) -> Option<(String, u64)> {
    if addr == 0 {
        return None;
    }

    let name = name?;
    if name == prefix || name.starts_with(&format!("{prefix}@")) {
        Some((name.to_string(), addr))
    } else {
        None
    }
}

fn find_plt_symbol_by_prefix(
    file: &object::File<'_>,
    prefix: &str,
) -> Result<Option<(String, u64)>> {
    let Some(rela_plt) = file
        .section_by_name(".rela.plt")
        .or_else(|| file.section_by_name(".rela.plt.sec"))
    else {
        return Ok(None);
    };
    let Some(dynsym) = file.section_by_name(".dynsym") else {
        return Ok(None);
    };
    let Some(dynstr) = file.section_by_name(".dynstr") else {
        return Ok(None);
    };

    let plt_addr = if let Some(plt_sec) = file.section_by_name(".plt.sec") {
        plt_sec.address()
    } else if let Some(plt) = file.section_by_name(".plt") {
        plt.address() + 16
    } else {
        return Ok(None);
    };

    let rela_data = rela_plt
        .data()
        .context("failed to read .rela.plt section data")?;
    let dynsym_data = dynsym
        .data()
        .context("failed to read .dynsym section data")?;
    let dynstr_data = dynstr
        .data()
        .context("failed to read .dynstr section data")?;

    for (reloc_index, rela) in rela_data.chunks_exact(24).enumerate() {
        let r_info = read_u64_le(rela, 8)?;
        let symbol_index = (r_info >> 32) as usize;
        let Some(name) = dynsym_name(dynsym_data, dynstr_data, symbol_index)? else {
            continue;
        };

        if name == prefix || name.starts_with(&format!("{prefix}@")) {
            return Ok(Some((
                format!("{prefix}@plt"),
                plt_addr + reloc_index as u64 * 16,
            )));
        }
    }

    Ok(None)
}

fn dynsym_name<'a>(
    dynsym: &[u8],
    dynstr: &'a [u8],
    symbol_index: usize,
) -> Result<Option<&'a str>> {
    let offset = symbol_index * 24;
    if offset + 24 > dynsym.len() {
        return Ok(None);
    }

    let name_offset = read_u32_le(dynsym, offset)? as usize;
    if name_offset == 0 || name_offset >= dynstr.len() {
        return Ok(None);
    }

    let name_end = dynstr[name_offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|end| name_offset + end)
        .unwrap_or(dynstr.len());
    let name = std::str::from_utf8(&dynstr[name_offset..name_end])
        .context("dynamic symbol name is not valid UTF-8")?;

    Ok(Some(name))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .context("ELF data ended unexpectedly")?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("slice length is 4"),
    ))
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .context("ELF data ended unexpectedly")?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("slice length is 8"),
    ))
}

fn elf_file_type_from_bytes(data: &[u8]) -> Result<ElfFileType> {
    let ident = data.get(0..16).context("ELF header ended unexpectedly")?;
    if ident.get(0..4) != Some(b"\x7fELF") {
        return Ok(ElfFileType::Other);
    }

    let endian = ident[5];
    let e_type = data.get(16..18).context("ELF header ended unexpectedly")?;
    let e_type = match endian {
        1 => u16::from_le_bytes(e_type.try_into().expect("slice length is 2")),
        2 => u16::from_be_bytes(e_type.try_into().expect("slice length is 2")),
        _ => return Ok(ElfFileType::Other),
    };

    match e_type {
        object::elf::ET_EXEC => Ok(ElfFileType::Executable),
        object::elf::ET_DYN => Ok(ElfFileType::PositionIndependentExecutable),
        _ => Ok(ElfFileType::Other),
    }
}

#[cfg(test)]
mod tests {
    use super::{elf_file_type_from_bytes, sort_and_dedup_symbols, ElfFileType, ElfSymbol};

    #[test]
    fn detects_executable_elf_type() {
        let mut header = minimal_elf_header(object::elf::ET_EXEC);

        assert_eq!(
            elf_file_type_from_bytes(&header).unwrap(),
            ElfFileType::Executable
        );

        header[16] = 0;
        header[17] = 0;
        assert_eq!(
            elf_file_type_from_bytes(&header).unwrap(),
            ElfFileType::Other
        );
    }

    #[test]
    fn detects_position_independent_elf_type() {
        let header = minimal_elf_header(object::elf::ET_DYN);

        assert_eq!(
            elf_file_type_from_bytes(&header).unwrap(),
            ElfFileType::PositionIndependentExecutable
        );
    }

    #[test]
    fn symbol_sorting_orders_by_address_and_deduplicates_name_address_pairs() {
        let mut symbols = vec![
            ElfSymbol {
                name: "later".to_string(),
                addr: 0x2000,
                size: 0x10,
            },
            ElfSymbol {
                name: "first".to_string(),
                addr: 0x1000,
                size: 0x20,
            },
            ElfSymbol {
                name: "first".to_string(),
                addr: 0x1000,
                size: 0x20,
            },
        ];

        sort_and_dedup_symbols(&mut symbols);

        assert_eq!(
            symbols,
            vec![
                ElfSymbol {
                    name: "first".to_string(),
                    addr: 0x1000,
                    size: 0x20,
                },
                ElfSymbol {
                    name: "later".to_string(),
                    addr: 0x2000,
                    size: 0x10,
                },
            ]
        );
    }

    fn minimal_elf_header(e_type: u16) -> Vec<u8> {
        let mut header = vec![0; 18];
        header[0..4].copy_from_slice(b"\x7fELF");
        header[4] = 2;
        header[5] = 1;
        header[6] = 1;
        header[16..18].copy_from_slice(&e_type.to_le_bytes());
        header
    }
}
