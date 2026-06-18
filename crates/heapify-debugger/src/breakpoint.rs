use super::*;

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
}

#[derive(Debug, Clone)]
pub enum BreakpointOwner {
    Allocator(BreakpointKind),
    UserInstructionStepOver {
        command_id: LiveCommandId,
        from_rip: u64,
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
        }
    }
}

pub struct ManagedBreakpoint {
    pub breakpoint: Breakpoint,
    pub owners: Vec<BreakpointOwner>,
}

#[derive(Default)]
pub struct BreakpointManager {
    pub(crate) breakpoints: HashMap<u64, ManagedBreakpoint>,
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
