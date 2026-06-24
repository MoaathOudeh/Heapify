use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserBreakpointId(pub u64);

impl UserBreakpointId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserBreakpointSpec {
    Address(u64),
    Symbol(String),
    SourceLine { path: String, line: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBreakpointResolution {
    pub requested_path: String,
    pub requested_line: u64,
    pub resolved_path: String,
    pub resolved_line: u64,
    pub resolved_address: u64,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserBreakpoint {
    pub id: UserBreakpointId,
    pub spec: UserBreakpointSpec,
    pub resolved_address: u64,
    pub enabled: bool,
    pub hit_count: u64,
    pub label: String,
    pub resolved_symbol: Option<String>,
    pub source: Option<SourceLocation>,
    pub source_resolution: Option<SourceBreakpointResolution>,
}

impl UserBreakpoint {
    pub fn summary_line(&self) -> String {
        let enabled = if self.enabled { "y" } else { "n" };
        format!(
            "{:<4} {:<3} {:<6} 0x{:x} {}",
            self.id.as_u64(),
            enabled,
            self.hit_count,
            self.resolved_address,
            self.label
        )
    }

    pub fn location_line(&self) -> String {
        if let Some(source) = self.source_summary() {
            if let Some(symbol) = self.resolved_symbol.as_deref() {
                return format!("0x{:x} ({source}; {symbol})", self.resolved_address);
            }
            return format!("0x{:x} ({source})", self.resolved_address);
        }
        format!("0x{:x} ({})", self.resolved_address, self.label)
    }

    pub fn source_summary(&self) -> Option<String> {
        self.source_resolution
            .as_ref()
            .map(|resolution| format!("{}:{}", resolution.resolved_path, resolution.resolved_line))
            .or_else(|| {
                self.source.as_ref().and_then(|source| {
                    let file = source.file.as_deref()?;
                    let line = source.line?;
                    Some(format!("{file}:{line}"))
                })
            })
    }
}

pub struct Breakpoint {
    pub addr: u64,
    pub original_byte: u8,
    pub enabled: bool,
}

impl Breakpoint {
    pub fn new(addr: u64) -> Self {
        Self {
            addr,
            original_byte: 0,
            enabled: false,
        }
    }

    pub fn enable(&mut self, pid: Pid) -> Result<()> {
        if self.enabled {
            return Ok(());
        }

        let word = read_word(pid, self.addr)?;
        self.original_byte = (word & 0xff) as u8;

        let patched = (word & !0xff) | 0xcc;
        write_word(pid, self.addr, patched)?;

        self.enabled = true;
        Ok(())
    }

    pub fn disable(&mut self, pid: Pid) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let word = read_word(pid, self.addr)?;
        let restored = (word & !0xff) | u64::from(self.original_byte);
        write_word(pid, self.addr, restored)?;

        self.enabled = false;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum BreakpointKind {
    MallocEntry,
    FreeEntry,
    CallocEntry,
    ReallocEntry,
    MallocReturn {
        requested_size: u64,
        event_id: usize,
        caller_addr: Option<u64>,
    },
    FreeReturn {
        ptr: u64,
        event_id: usize,
        caller_addr: Option<u64>,
    },
    CallocReturn {
        nmemb: u64,
        size: u64,
        event_id: usize,
        caller_addr: Option<u64>,
    },
    ReallocReturn {
        old_ptr: u64,
        new_size: u64,
        event_id: usize,
        old_chunk: Option<GlibcChunkHeader>,
        caller_addr: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointPurpose {
    ManagedAllocatorEntry,
    ManagedAllocatorReturn,
    UserInstructionStepOver,
    UserPersistent,
}

#[derive(Debug, Clone)]
pub enum BreakpointOwner {
    Allocator(BreakpointKind),
    UserInstructionStepOver {
        command_id: LiveCommandId,
        from_rip: u64,
    },
    UserPersistent {
        breakpoint_id: UserBreakpointId,
    },
}

impl BreakpointOwner {
    pub(crate) fn purpose(&self) -> BreakpointPurpose {
        match self {
            BreakpointOwner::Allocator(
                BreakpointKind::MallocEntry
                | BreakpointKind::FreeEntry
                | BreakpointKind::CallocEntry
                | BreakpointKind::ReallocEntry,
            ) => BreakpointPurpose::ManagedAllocatorEntry,
            BreakpointOwner::Allocator(_) => BreakpointPurpose::ManagedAllocatorReturn,
            BreakpointOwner::UserInstructionStepOver { .. } => {
                BreakpointPurpose::UserInstructionStepOver
            }
            BreakpointOwner::UserPersistent { .. } => BreakpointPurpose::UserPersistent,
        }
    }
}

pub struct ManagedBreakpoint {
    pub breakpoint: Breakpoint,
    pub owners: Vec<BreakpointOwner>,
}

fn is_duplicate_user_persistent_owner(
    existing: &[BreakpointOwner],
    owner: &BreakpointOwner,
) -> bool {
    let BreakpointOwner::UserPersistent { breakpoint_id } = owner else {
        return false;
    };
    existing.iter().any(|existing_owner| {
        matches!(
            existing_owner,
            BreakpointOwner::UserPersistent {
                breakpoint_id: existing_id
            } if existing_id == breakpoint_id
        )
    })
}

#[derive(Default)]
pub struct BreakpointManager {
    pub(crate) breakpoints: HashMap<u64, ManagedBreakpoint>,
    user_breakpoints: std::collections::BTreeMap<UserBreakpointId, UserBreakpoint>,
    next_user_breakpoint_id: u64,
}

impl BreakpointManager {
    pub fn set_breakpoint(&mut self, pid: Pid, addr: u64, kind: BreakpointKind) -> Result<()> {
        self.add_owner(pid, addr, BreakpointOwner::Allocator(kind))
    }

    pub(crate) fn set_user_step_over_breakpoint(
        &mut self,
        pid: Pid,
        addr: u64,
        command_id: LiveCommandId,
        from_rip: u64,
    ) -> Result<()> {
        self.add_owner(
            pid,
            addr,
            BreakpointOwner::UserInstructionStepOver {
                command_id,
                from_rip,
            },
        )
    }

    fn add_owner(&mut self, pid: Pid, addr: u64, owner: BreakpointOwner) -> Result<()> {
        if let Some(managed) = self.breakpoints.get_mut(&addr) {
            if is_duplicate_user_persistent_owner(&managed.owners, &owner) {
                return Ok(());
            }
            managed.owners.push(owner);
            managed
                .breakpoint
                .enable(pid)
                .with_context(|| format!("failed to enable breakpoint at 0x{addr:x}"))?;
            return Ok(());
        }

        let mut breakpoint = Breakpoint::new(addr);
        breakpoint
            .enable(pid)
            .with_context(|| format!("failed to enable breakpoint at 0x{addr:x}"))?;

        self.breakpoints.insert(
            addr,
            ManagedBreakpoint {
                breakpoint,
                owners: vec![owner],
            },
        );
        Ok(())
    }

    pub fn add_user_breakpoint(
        &mut self,
        pid: Pid,
        spec: UserBreakpointSpec,
        resolved_address: u64,
        label: String,
        resolved_symbol: Option<String>,
        source: Option<SourceLocation>,
        source_resolution: Option<SourceBreakpointResolution>,
    ) -> Result<UserBreakpoint> {
        let id = UserBreakpointId(self.next_user_breakpoint_id.max(1));
        self.next_user_breakpoint_id = id.0 + 1;
        let breakpoint = UserBreakpoint {
            id,
            spec,
            resolved_address,
            enabled: true,
            hit_count: 0,
            label,
            resolved_symbol,
            source,
            source_resolution,
        };
        self.user_breakpoints.insert(id, breakpoint.clone());
        self.add_owner(
            pid,
            resolved_address,
            BreakpointOwner::UserPersistent { breakpoint_id: id },
        )?;
        Ok(breakpoint)
    }

    pub fn list_user_breakpoints(&self) -> Vec<UserBreakpoint> {
        self.user_breakpoints.values().cloned().collect()
    }

    pub fn get_user_breakpoint(&self, id: UserBreakpointId) -> Option<&UserBreakpoint> {
        self.user_breakpoints.get(&id)
    }

    pub fn enable_user_breakpoint(
        &mut self,
        pid: Pid,
        id: UserBreakpointId,
    ) -> Result<UserBreakpoint> {
        let (addr, was_enabled) = {
            let breakpoint = self
                .user_breakpoints
                .get_mut(&id)
                .with_context(|| format!("unknown breakpoint id {}", id.as_u64()))?;
            let was_enabled = breakpoint.enabled;
            breakpoint.enabled = true;
            (breakpoint.resolved_address, was_enabled)
        };
        if !was_enabled {
            self.add_owner(
                pid,
                addr,
                BreakpointOwner::UserPersistent { breakpoint_id: id },
            )?;
        }
        Ok(self
            .user_breakpoints
            .get(&id)
            .expect("breakpoint exists")
            .clone())
    }

    pub fn disable_user_breakpoint(
        &mut self,
        pid: Pid,
        id: UserBreakpointId,
    ) -> Result<UserBreakpoint> {
        let (addr, was_enabled) = {
            let breakpoint = self
                .user_breakpoints
                .get_mut(&id)
                .with_context(|| format!("unknown breakpoint id {}", id.as_u64()))?;
            let was_enabled = breakpoint.enabled;
            breakpoint.enabled = false;
            (breakpoint.resolved_address, was_enabled)
        };
        if was_enabled {
            self.remove_owner_at(pid, addr, |owner| {
                matches!(owner, BreakpointOwner::UserPersistent { breakpoint_id } if *breakpoint_id == id)
            })?;
        }
        Ok(self
            .user_breakpoints
            .get(&id)
            .expect("breakpoint exists")
            .clone())
    }

    pub fn delete_user_breakpoint(
        &mut self,
        pid: Pid,
        id: UserBreakpointId,
    ) -> Result<UserBreakpoint> {
        let breakpoint = self
            .user_breakpoints
            .remove(&id)
            .with_context(|| format!("unknown breakpoint id {}", id.as_u64()))?;
        if breakpoint.enabled {
            self.remove_owner_at(pid, breakpoint.resolved_address, |owner| {
                matches!(owner, BreakpointOwner::UserPersistent { breakpoint_id } if *breakpoint_id == id)
            })?;
        }
        Ok(breakpoint)
    }

    pub fn persistent_user_owners_at(&self, address: u64) -> Vec<UserBreakpointId> {
        self.breakpoints
            .get(&address)
            .map(|managed| {
                managed
                    .owners
                    .iter()
                    .filter_map(|owner| match owner {
                        BreakpointOwner::UserPersistent { breakpoint_id } => Some(*breakpoint_id),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn record_user_breakpoint_hits(
        &mut self,
        ids: &[UserBreakpointId],
    ) -> Vec<UserBreakpoint> {
        let mut breakpoints = Vec::new();
        for id in ids {
            if let Some(breakpoint) = self.user_breakpoints.get_mut(id) {
                if breakpoint.enabled {
                    breakpoint.hit_count += 1;
                    breakpoints.push(breakpoint.clone());
                }
            }
        }
        breakpoints.sort_by_key(|breakpoint| breakpoint.id);
        breakpoints
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.breakpoints.contains_key(&addr)
    }

    pub fn get_mut(&mut self, addr: u64) -> Option<&mut ManagedBreakpoint> {
        self.breakpoints.get_mut(&addr)
    }

    pub(crate) fn remove_owner_at(
        &mut self,
        pid: Pid,
        addr: u64,
        predicate: impl FnMut(&BreakpointOwner) -> bool,
    ) -> Result<Option<BreakpointOwner>> {
        let mut should_remove_physical = false;
        let removed = if let Some(managed) = self.breakpoints.get_mut(&addr) {
            let Some(index) = managed.owners.iter().position(predicate) else {
                return Ok(None);
            };
            let owner = managed.owners.remove(index);
            if managed.owners.is_empty() {
                managed
                    .breakpoint
                    .disable(pid)
                    .with_context(|| format!("failed to disable breakpoint at 0x{addr:x}"))?;
                should_remove_physical = true;
            }
            Some(owner)
        } else {
            None
        };
        if should_remove_physical {
            self.breakpoints.remove(&addr);
        }
        Ok(removed)
    }

    pub(crate) fn remove_user_step_over_breakpoint(&mut self, pid: Pid, addr: u64) -> Result<()> {
        self.remove_owner_at(pid, addr, |owner| {
            matches!(owner, BreakpointOwner::UserInstructionStepOver { .. })
        })?;
        Ok(())
    }

    pub(crate) fn user_step_over_owner(&self, addr: u64) -> Option<(LiveCommandId, u64)> {
        self.breakpoints
            .get(&addr)?
            .owners
            .iter()
            .find_map(|owner| match owner {
                BreakpointOwner::UserInstructionStepOver {
                    command_id,
                    from_rip,
                } => Some((*command_id, *from_rip)),
                _ => None,
            })
    }

    pub(crate) fn allocator_owner(&self, addr: u64) -> Option<BreakpointKind> {
        self.breakpoints
            .get(&addr)?
            .owners
            .iter()
            .find_map(|owner| match owner {
                BreakpointOwner::Allocator(kind) => Some(kind.clone()),
                _ => None,
            })
    }

    pub(crate) fn all_breakpoints_rearmed(&self) -> bool {
        self.breakpoints
            .values()
            .all(|managed| managed.breakpoint.enabled)
    }

    pub(crate) fn has_temporary_return_breakpoints(&self) -> bool {
        self.breakpoints.values().any(|managed| {
            managed
                .owners
                .iter()
                .any(|owner| matches!(owner.purpose(), BreakpointPurpose::ManagedAllocatorReturn))
        })
    }
}
