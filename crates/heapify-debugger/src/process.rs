use super::*;

#[derive(Debug, Clone)]
pub struct TargetCommand {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
}

impl TargetCommand {
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchMode {
    Normal,
    LdPreload,
    CustomLoader,
    CustomLoaderWithPreload,
}

impl LaunchMode {
    pub fn as_str(self) -> &'static str {
        match self {
            LaunchMode::Normal => "normal",
            LaunchMode::LdPreload => "ld_preload",
            LaunchMode::CustomLoader => "custom_loader",
            LaunchMode::CustomLoaderWithPreload => "custom_loader_with_preload",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchConfig {
    pub target_program: PathBuf,
    pub target_args: Vec<String>,
    pub loader_path: Option<PathBuf>,
    pub library_path: Option<PathBuf>,
    pub preload_path: Option<PathBuf>,
    pub supplied_libc_path: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub clear_env: bool,
    pub set_env: Vec<(String, String)>,
    pub unset_env: Vec<String>,
    pub stdin: StdinConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlan {
    pub exec_program: PathBuf,
    pub exec_args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub clear_env: bool,
    pub env_unsets: Vec<String>,
    pub env_overrides: Vec<(String, String)>,
    pub target_program_for_symbols: PathBuf,
    pub launch_mode: LaunchMode,
    pub effective_library_path: Option<PathBuf>,
    pub loader_path: Option<PathBuf>,
    pub preload_path: Option<PathBuf>,
    pub stdin: StdinConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdinConfig {
    Inherit,
    File(PathBuf),
    Text(String),
}

pub fn build_exec_plan(config: &LaunchConfig) -> Result<ExecPlan> {
    let launch_mode = match (&config.loader_path, &config.preload_path) {
        (None, None) => LaunchMode::Normal,
        (None, Some(_)) => LaunchMode::LdPreload,
        (Some(_), None) => LaunchMode::CustomLoader,
        (Some(_), Some(_)) => LaunchMode::CustomLoaderWithPreload,
    };
    let effective_library_path = config.loader_path.as_ref().and_then(|_| {
        config.library_path.clone().or_else(|| {
            config
                .supplied_libc_path
                .as_ref()
                .and_then(|path| parent_dir(path))
        })
    });
    let mut env_overrides = config.set_env.clone();
    if let Some(preload_path) = &config.preload_path {
        env_overrides.push((
            "LD_PRELOAD".to_string(),
            preload_path.to_string_lossy().into_owned(),
        ));
    }

    let (exec_program, exec_args) = if let Some(loader_path) = &config.loader_path {
        let mut exec_args = vec![loader_path.to_string_lossy().into_owned()];
        if let Some(library_path) = &effective_library_path {
            exec_args.push("--library-path".to_string());
            exec_args.push(library_path.to_string_lossy().into_owned());
        }
        exec_args.push(config.target_program.to_string_lossy().into_owned());
        exec_args.extend(config.target_args.iter().cloned());
        (loader_path.clone(), exec_args)
    } else {
        let mut exec_args = vec![config.target_program.to_string_lossy().into_owned()];
        exec_args.extend(config.target_args.iter().cloned());
        (config.target_program.clone(), exec_args)
    };

    Ok(ExecPlan {
        exec_program,
        exec_args,
        cwd: config.cwd.clone(),
        clear_env: config.clear_env,
        env_unsets: config.unset_env.clone(),
        env_overrides,
        target_program_for_symbols: config.target_program.clone(),
        launch_mode,
        effective_library_path,
        loader_path: config.loader_path.clone(),
        preload_path: config.preload_path.clone(),
        stdin: config.stdin.clone(),
    })
}

fn parent_dir(path: &Path) -> Option<PathBuf> {
    path.parent().map(|parent| {
        if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_path_buf()
        }
    })
}
