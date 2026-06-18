use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TraceModeArg {
    Plt,
    Libc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AllocatorViewsPresetArg {
    None,
    Basic,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorViewsPreset {
    None,
    Basic,
    Full,
}

impl AllocatorViewsPreset {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AllocatorViewsPreset::None => "none",
            AllocatorViewsPreset::Basic => "basic",
            AllocatorViewsPreset::Full => "full",
        }
    }
}

impl From<AllocatorViewsPresetArg> for AllocatorViewsPreset {
    fn from(value: AllocatorViewsPresetArg) -> Self {
        match value {
            AllocatorViewsPresetArg::None => AllocatorViewsPreset::None,
            AllocatorViewsPresetArg::Basic => AllocatorViewsPreset::Basic,
            AllocatorViewsPresetArg::Full => AllocatorViewsPreset::Full,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelectedMainArenaTopOffset {
    User { offset: u64 },
    Profile { offset: u64, profile_name: String },
    Unavailable,
}

#[derive(Debug, Clone)]
pub(crate) struct RenderConfig {
    pub(crate) show_chunks: bool,
    pub(crate) show_tracker_notes: bool,
    pub(crate) show_explanations: bool,
    pub(crate) show_layout: bool,
    pub(crate) max_layout_chunks: usize,
    pub(crate) show_tcache_candidates: bool,
    pub(crate) max_tcache_chain: usize,
    pub(crate) max_fastbin_chain: usize,
    pub(crate) max_unsorted_chain: usize,
    pub(crate) max_regular_bins: usize,
    pub(crate) max_smallbin_chain: usize,
    pub(crate) max_largebin_chain: usize,
    pub(crate) show_tcache_struct_candidate: bool,
    pub(crate) show_main_arena_candidate: bool,
    pub(crate) main_arena_offset: Option<u64>,
    pub(crate) show_arena_experiment: bool,
    pub(crate) show_fastbin_experiment: bool,
    pub(crate) show_unsorted_experiment: bool,
    pub(crate) show_bin_experiment: bool,
    pub(crate) show_unsorted_bin: bool,
    pub(crate) show_fastbins: bool,
    pub(crate) show_regular_bins: bool,
    pub(crate) show_smallbins: bool,
    pub(crate) show_largebins: bool,
    pub(crate) show_heap_scan: bool,
    pub(crate) show_main_arena_top_candidate: bool,
    pub(crate) main_arena_top_offset: Option<u64>,
    pub(crate) trace_mode: Option<TraceModeArg>,
    pub(crate) libc_symbols: bool,
    pub(crate) supplied_libc_path: Option<PathBuf>,
    pub(crate) loader_path: Option<PathBuf>,
    pub(crate) library_path: Option<PathBuf>,
    pub(crate) preload_path: Option<PathBuf>,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) clear_env: bool,
    pub(crate) set_env: Vec<(String, String)>,
    pub(crate) unset_env: Vec<String>,
    pub(crate) stdin: StdinConfig,
    pub(crate) glibc_profile_request: String,
    pub(crate) glibc_profile: GlibcProfile,
    pub(crate) allocator_views_preset: AllocatorViewsPreset,
    pub(crate) json: bool,
    pub(crate) json_out: Option<PathBuf>,
    pub(crate) live_tui: bool,
    pub(crate) break_conditions: Vec<AllocatorBreakCondition>,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            show_chunks: true,
            show_tracker_notes: true,
            show_explanations: true,
            show_layout: false,
            max_layout_chunks: 32,
            show_tcache_candidates: false,
            max_tcache_chain: 32,
            max_fastbin_chain: 32,
            max_unsorted_chain: 32,
            max_regular_bins: 16,
            max_smallbin_chain: 32,
            max_largebin_chain: 32,
            show_tcache_struct_candidate: false,
            show_main_arena_candidate: false,
            main_arena_offset: None,
            show_arena_experiment: false,
            show_fastbin_experiment: false,
            show_unsorted_experiment: false,
            show_bin_experiment: false,
            show_unsorted_bin: false,
            show_fastbins: false,
            show_regular_bins: false,
            show_smallbins: false,
            show_largebins: false,
            show_heap_scan: false,
            show_main_arena_top_candidate: false,
            main_arena_top_offset: None,
            trace_mode: None,
            libc_symbols: false,
            supplied_libc_path: None,
            loader_path: None,
            library_path: None,
            preload_path: None,
            cwd: None,
            clear_env: false,
            set_env: Vec::new(),
            unset_env: Vec::new(),
            stdin: StdinConfig::Inherit,
            glibc_profile_request: GLIBC_X86_64_MODERN.name.to_string(),
            glibc_profile: GLIBC_X86_64_MODERN,
            allocator_views_preset: AllocatorViewsPreset::None,
            json: false,
            json_out: None,
            live_tui: false,
            break_conditions: Vec::new(),
        }
    }
}

impl RenderConfig {
    pub(crate) fn events_only(&self) -> bool {
        !self.show_chunks
            && !self.show_tracker_notes
            && !self.show_explanations
            && !self.show_layout
    }

    pub(crate) fn json_enabled(&self) -> bool {
        self.json || self.json_out.is_some()
    }
}
