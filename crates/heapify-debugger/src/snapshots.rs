use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSnapshot {
    pub arch: RegisterArch,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
    pub registers: Vec<RegisterValue>,
}

impl RegisterSnapshot {
    pub fn get(&self, name: &str) -> Option<u64> {
        self.registers
            .iter()
            .find(|register| register.name == name)
            .map(|register| register.value)
    }

    pub fn summary_line(&self) -> String {
        let rip = format_register_value_hex(self.instruction_pointer);
        let rsp = format_register_value_hex(self.stack_pointer);
        let rbp = format_register_value_hex(self.frame_pointer);
        let rax = self
            .get("rax")
            .map(format_register_value_hex)
            .unwrap_or_else(|| "unknown".to_string());
        format!("rip={rip} rsp={rsp} rbp={rbp} rax={rax}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterArch {
    X86_64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterValue {
    pub name: String,
    pub value: u64,
    pub role: Option<RegisterRole>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterRole {
    InstructionPointer,
    StackPointer,
    FramePointer,
    ReturnValue,
    Argument,
    General,
    Flags,
}

pub fn format_register_value_hex(value: u64) -> String {
    format!("0x{value:x}")
}

pub const DEFAULT_STACK_SNAPSHOT_WORDS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSnapshot {
    pub stack_pointer: u64,
    pub word_size: u8,
    pub words: Vec<StackWord>,
    pub truncated: bool,
    pub read_error: Option<String>,
}

pub const DEFAULT_DISASSEMBLY_BEFORE_BYTES: usize = 96;
pub const DEFAULT_DISASSEMBLY_AFTER_BYTES: usize = 160;
pub const DEFAULT_DISASSEMBLY_MAX_INSTRUCTIONS: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassemblySnapshot {
    pub instruction_pointer: u64,
    pub start_address: u64,
    pub end_address: u64,
    pub lines: Vec<DisassemblyLine>,
    pub truncated_before: bool,
    pub truncated_after: bool,
    pub read_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassemblyLine {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub text: String,
    pub is_current: bool,
    pub flow_control: Option<DisassemblyFlowControl>,
    pub target: Option<u64>,
    pub target_annotation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisassemblyFlowControl {
    Call,
    ConditionalBranch,
    UnconditionalBranch,
    Return,
    Interrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub instruction_pointer: u64,
    pub length: u32,
    pub flow_control: String,
    pub is_call: bool,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackWord {
    pub offset_from_sp: i64,
    pub address: u64,
    pub value: u64,
    pub annotation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMapEntry {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub device: Option<String>,
    pub inode: Option<u64>,
    pub pathname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMapsSnapshot {
    pub entries: Vec<ProcessMapEntry>,
}

pub fn read_register_snapshot(pid: Pid) -> Result<RegisterSnapshot> {
    let regs = ptrace::getregs(pid).context("failed to read child registers")?;
    Ok(register_snapshot_from_x86_64_regs(regs))
}

pub fn read_process_maps_snapshot(pid: Pid) -> Result<ProcessMapsSnapshot> {
    Ok(ProcessMapsSnapshot {
        entries: read_process_maps(pid)?
            .into_iter()
            .map(ProcessMapEntry::from)
            .collect(),
    })
}

impl From<MemoryMapping> for ProcessMapEntry {
    fn from(mapping: MemoryMapping) -> Self {
        Self {
            start: mapping.start,
            end: mapping.end,
            permissions: mapping.permissions,
            offset: mapping.offset,
            device: Some(mapping.dev),
            inode: Some(mapping.inode),
            pathname: mapping.pathname,
        }
    }
}

pub fn read_stack_snapshot(pid: Pid, stack_pointer: u64, word_count: usize) -> StackSnapshot {
    read_stack_snapshot_with_reader(stack_pointer, word_count, |addr| read_word(pid, addr))
}

pub trait TargetMemoryReader {
    fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>>;
}

struct PtraceMemoryReader {
    pid: Pid,
}

impl TargetMemoryReader for PtraceMemoryReader {
    fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        read_target_memory(self.pid, address, size)
    }
}

pub fn read_disassembly_snapshot(
    pid: Pid,
    rip: u64,
    before_bytes: usize,
    after_bytes: usize,
) -> DisassemblySnapshot {
    read_disassembly_snapshot_with_reader(
        &PtraceMemoryReader { pid },
        rip,
        before_bytes,
        after_bytes,
        DEFAULT_DISASSEMBLY_MAX_INSTRUCTIONS,
    )
}

pub fn read_disassembly_snapshot_with_reader(
    reader: &impl TargetMemoryReader,
    rip: u64,
    before_bytes: usize,
    after_bytes: usize,
    max_instructions: usize,
) -> DisassemblySnapshot {
    let start_address = rip.saturating_sub(before_bytes as u64);
    let requested_before = rip.saturating_sub(start_address) as usize;
    let requested_size = requested_before.saturating_add(after_bytes.max(15));
    let mut snapshot = DisassemblySnapshot {
        instruction_pointer: rip,
        start_address,
        end_address: start_address,
        lines: Vec::new(),
        truncated_before: start_address == 0 && before_bytes > requested_before,
        truncated_after: false,
        read_error: None,
    };

    let bytes = match reader.read_memory(start_address, requested_size) {
        Ok(bytes) => bytes,
        Err(err) => {
            snapshot.truncated_before = requested_before > 0;
            snapshot.truncated_after = after_bytes > 0;
            snapshot.read_error = Some(err.to_string());
            return snapshot;
        }
    };
    snapshot.end_address = start_address.saturating_add(bytes.len() as u64);

    let rip_offset = rip.saturating_sub(start_address) as usize;
    if rip_offset >= bytes.len() {
        snapshot.truncated_after = true;
        snapshot.read_error = Some("instruction pointer is outside readable window".to_string());
        return snapshot;
    }

    let before_window = &bytes[..rip_offset];
    let after_window = &bytes[rip_offset..];
    let current_and_after_limit = max_instructions.saturating_add(1);
    let mut forward_lines = decode_disassembly_sequence(rip, after_window, current_and_after_limit);
    if forward_lines.is_empty() {
        snapshot.truncated_after = true;
        snapshot.read_error = Some("failed to decode instruction at RIP".to_string());
        return snapshot;
    }
    if decoded_bytes_len(&forward_lines) < after_window.len() {
        snapshot.truncated_after = true;
    }

    let before_limit = max_instructions.saturating_sub(1) / 2;
    let preceding = recover_preceding_disassembly(start_address, before_window, rip, before_limit);
    if before_window.is_empty() {
        snapshot.truncated_before = snapshot.truncated_before || before_bytes > 0;
    } else if preceding.is_empty() {
        snapshot.truncated_before = true;
    }

    let mut lines = preceding;
    for line in &mut forward_lines {
        line.is_current = line.address == rip;
    }
    lines.extend(forward_lines);
    if lines.len() > max_instructions {
        let original_len = lines.len();
        let current_index = lines.iter().position(|line| line.is_current).unwrap_or(0);
        let before_count = before_limit.min(current_index);
        let after_count = max_instructions.saturating_sub(before_count);
        let start = current_index.saturating_sub(before_count);
        let end = (start + after_count).min(lines.len());
        lines = lines[start..end].to_vec();
        snapshot.truncated_before = snapshot.truncated_before || start > 0;
        snapshot.truncated_after = snapshot.truncated_after || end < original_len;
    }

    snapshot.lines = lines;
    snapshot
}

fn recover_preceding_disassembly(
    start_address: u64,
    bytes: &[u8],
    rip: u64,
    max_lines: usize,
) -> Vec<DisassemblyLine> {
    if bytes.is_empty() || max_lines == 0 {
        return Vec::new();
    }

    let mut best = Vec::new();
    for offset in 0..bytes.len() {
        let candidate_addr = start_address.saturating_add(offset as u64);
        let decoded = decode_disassembly_sequence(candidate_addr, &bytes[offset..], max_lines + 32);
        let lands_on_rip = decoded.iter().any(|line| {
            let end = line.address.saturating_add(line.bytes.len() as u64);
            end == rip
        });
        let stops_at_rip = decoded
            .last()
            .map(|line| line.address.saturating_add(line.bytes.len() as u64) == rip)
            .unwrap_or(false);
        if lands_on_rip && stops_at_rip {
            best = decoded;
            break;
        }
    }

    if best.len() > max_lines {
        best[best.len() - max_lines..].to_vec()
    } else {
        best
    }
}

fn decode_disassembly_sequence(
    start_address: u64,
    bytes: &[u8],
    max_instructions: usize,
) -> Vec<DisassemblyLine> {
    let mut decoder = Decoder::with_ip(64, bytes, start_address, DecoderOptions::NONE);
    let mut lines = Vec::new();
    while decoder.can_decode() && lines.len() < max_instructions {
        let offset = decoder.position();
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.len() == 0 {
            break;
        }
        let end = offset.saturating_add(instruction.len());
        if end > bytes.len() {
            break;
        }
        lines.push(disassembly_line_from_iced(
            instruction,
            bytes[offset..end].to_vec(),
        ));
    }
    lines
}

fn decoded_bytes_len(lines: &[DisassemblyLine]) -> usize {
    lines.iter().map(|line| line.bytes.len()).sum()
}

fn disassembly_line_from_iced(instruction: Instruction, bytes: Vec<u8>) -> DisassemblyLine {
    let flow_control = disassembly_flow_control(instruction.flow_control());
    let target = direct_branch_target(&instruction);
    let mut formatter = NasmFormatter::new();
    let mut text = String::new();
    formatter.format(&instruction, &mut text);
    let (mnemonic, operands) = split_instruction_text(&text);
    DisassemblyLine {
        address: instruction.ip(),
        bytes,
        mnemonic,
        operands,
        text,
        is_current: false,
        flow_control,
        target,
        target_annotation: None,
    }
}

fn split_instruction_text(text: &str) -> (String, String) {
    let trimmed = text.trim();
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let mnemonic = parts.next().unwrap_or_default().to_string();
    let operands = parts.next().unwrap_or_default().trim().to_string();
    (mnemonic, operands)
}

fn disassembly_flow_control(flow_control: FlowControl) -> Option<DisassemblyFlowControl> {
    match flow_control {
        FlowControl::Call | FlowControl::IndirectCall => Some(DisassemblyFlowControl::Call),
        FlowControl::ConditionalBranch => Some(DisassemblyFlowControl::ConditionalBranch),
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
            Some(DisassemblyFlowControl::UnconditionalBranch)
        }
        FlowControl::Return => Some(DisassemblyFlowControl::Return),
        FlowControl::Interrupt => Some(DisassemblyFlowControl::Interrupt),
        _ => None,
    }
}

fn direct_branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.flow_control() {
        FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
            Some(instruction.near_branch_target())
        }
        _ => None,
    }
}

pub fn decode_instruction_at_rip(pid: Pid, rip: u64) -> Result<DecodedInstruction> {
    let mut bytes = [0u8; 15];
    for offset in (0..15).step_by(8) {
        let word = if offset == 0 {
            read_word(pid, rip)?
        } else {
            read_word(pid, rip + offset as u64).unwrap_or(0)
        };
        let word_bytes = word.to_le_bytes();
        let len = (15 - offset).min(8);
        bytes[offset..offset + len].copy_from_slice(&word_bytes[..len]);
    }
    decode_x86_64_instruction(rip, &bytes)
}

pub(crate) fn decode_x86_64_instruction(rip: u64, bytes: &[u8]) -> Result<DecodedInstruction> {
    let mut decoder = Decoder::with_ip(64, bytes, rip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() == 0 {
        bail!("failed to decode instruction at 0x{rip:x}");
    }
    Ok(decoded_instruction_from_iced(instruction))
}

fn decoded_instruction_from_iced(instruction: Instruction) -> DecodedInstruction {
    let flow_control = instruction.flow_control();
    let mut formatter = NasmFormatter::new();
    let mut text = String::new();
    formatter.format(&instruction, &mut text);
    DecodedInstruction {
        instruction_pointer: instruction.ip(),
        length: instruction.len() as u32,
        flow_control: format!("{flow_control:?}"),
        is_call: matches!(flow_control, FlowControl::Call | FlowControl::IndirectCall),
        text,
    }
}

pub(crate) fn decoded_instruction_fallthrough(instruction: &DecodedInstruction) -> u64 {
    instruction
        .instruction_pointer
        .saturating_add(u64::from(instruction.length))
}

pub(crate) fn read_stack_snapshot_with_reader(
    stack_pointer: u64,
    word_count: usize,
    mut read_word: impl FnMut(u64) -> Result<u64>,
) -> StackSnapshot {
    let mut snapshot = StackSnapshot {
        stack_pointer,
        word_size: 8,
        words: Vec::with_capacity(word_count),
        truncated: false,
        read_error: None,
    };

    for index in 0..word_count {
        let offset = (index as u64).saturating_mul(8);
        let Some(address) = stack_pointer.checked_add(offset) else {
            snapshot.truncated = true;
            snapshot.read_error = Some("stack address overflow".to_string());
            break;
        };

        match read_word(address) {
            Ok(value) => snapshot.words.push(StackWord {
                offset_from_sp: offset as i64,
                address,
                value,
                annotation: None,
            }),
            Err(err) => {
                snapshot.truncated = true;
                snapshot.read_error = Some(err.to_string());
                break;
            }
        }
    }

    snapshot
}

pub(crate) fn register_snapshot_from_x86_64_regs(regs: libc::user_regs_struct) -> RegisterSnapshot {
    let registers = vec![
        register_value("rip", regs.rip, RegisterRole::InstructionPointer),
        register_value("rsp", regs.rsp, RegisterRole::StackPointer),
        register_value("rbp", regs.rbp, RegisterRole::FramePointer),
        register_value("rax", regs.rax, RegisterRole::ReturnValue),
        register_value("rbx", regs.rbx, RegisterRole::General),
        register_value("rcx", regs.rcx, RegisterRole::Argument),
        register_value("rdx", regs.rdx, RegisterRole::Argument),
        register_value("rsi", regs.rsi, RegisterRole::Argument),
        register_value("rdi", regs.rdi, RegisterRole::Argument),
        register_value("r8", regs.r8, RegisterRole::Argument),
        register_value("r9", regs.r9, RegisterRole::Argument),
        register_value("r10", regs.r10, RegisterRole::General),
        register_value("r11", regs.r11, RegisterRole::General),
        register_value("r12", regs.r12, RegisterRole::General),
        register_value("r13", regs.r13, RegisterRole::General),
        register_value("r14", regs.r14, RegisterRole::General),
        register_value("r15", regs.r15, RegisterRole::General),
        register_value("eflags", regs.eflags, RegisterRole::Flags),
        register_value("orig_rax", regs.orig_rax, RegisterRole::General),
        register_value("cs", regs.cs, RegisterRole::General),
        register_value("ss", regs.ss, RegisterRole::General),
        register_value("ds", regs.ds, RegisterRole::General),
        register_value("es", regs.es, RegisterRole::General),
        register_value("fs", regs.fs, RegisterRole::General),
        register_value("gs", regs.gs, RegisterRole::General),
        register_value("fs_base", regs.fs_base, RegisterRole::General),
        register_value("gs_base", regs.gs_base, RegisterRole::General),
    ];

    RegisterSnapshot {
        arch: RegisterArch::X86_64,
        instruction_pointer: regs.rip,
        stack_pointer: regs.rsp,
        frame_pointer: regs.rbp,
        registers,
    }
}

fn register_value(name: &str, value: u64, role: RegisterRole) -> RegisterValue {
    RegisterValue {
        name: name.to_string(),
        value,
        role: Some(role),
    }
}
