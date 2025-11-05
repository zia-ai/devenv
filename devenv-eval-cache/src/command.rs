use futures::future::join_all;
use miette::Diagnostic;
use sqlx::SqlitePool;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, trace};

use crate::{
    db,
    internal_log::{InternalLog, Verbosity},
    op::Op,
};
use devenv_cache_core::{compute_file_hash, compute_string_hash};

#[derive(Error, Diagnostic, Debug)]
pub enum CommandError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

type OnStderr = Box<dyn Fn(&InternalLog) + Send>;

pub struct NixCommand<'a> {
    pool: &'a sqlx::SqlitePool,
    enable_caching: bool,
    force_refresh: bool,
    extra_paths: Vec<PathBuf>,
    excluded_paths: Vec<PathBuf>,
    on_stderr: Option<OnStderr>,
}

impl<'a> NixCommand<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self {
            pool,
            enable_caching: true,
            force_refresh: false,
            extra_paths: Vec::new(),
            excluded_paths: Vec::new(),
            on_stderr: None,
        }
    }

    /// Watch additional paths for changes.
    ///
    /// WARN: Be careful watching generated files.
    /// External tools like direnv are triggered solely by the modification date and don't compare file contents.
    /// Use [util::write_file_with_lock] to safely write such files.
    pub fn watch_path<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.extra_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Remove a path from being watched for changes.
    pub fn unwatch_path<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.excluded_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Force re-evaluation of the command.
    pub fn force_refresh(&mut self) -> &mut Self {
        self.force_refresh = true;
        self
    }

    /// Enable or disable eval caching.
    pub fn enable_eval_cache(&mut self, enable: bool) -> &mut Self {
        self.enable_caching = enable;
        self
    }

    pub fn on_stderr<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&InternalLog) + Send + 'static,
    {
        self.on_stderr = Some(Box::new(f));
        self
    }

    /// Run a (Nix) command with caching enabled.
    ///
    /// If the command has been run before and the files it depends on have not been modified,
    /// the cached output will be returned.
    pub async fn output(mut self, cmd: &'a mut Command) -> Result<Output, CommandError> {
        let raw_cmd = format!("{cmd:?}");
        let cmd_hash = compute_string_hash(&raw_cmd);

        // Check the cache if enabled
        let cache_miss_reason = if self.enable_caching && !self.force_refresh {
            match query_cached_output(self.pool, &cmd_hash, &raw_cmd, &self.extra_paths).await? {
                CacheCheckResult::Hit(output) => return Ok(output),
                CacheCheckResult::Miss(reason) => Some(reason),
            }
        } else {
            None
        };

        cmd.arg("-vv")
            .arg("--log-format")
            .arg("internal-json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(CommandError::Io)?;

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let stdout_reader = BufReader::new(stdout);
        let stderr_reader = BufReader::new(stderr);

        let stdout_thread = std::thread::spawn(move || {
            let mut output = Vec::new();
            let mut lines = stdout_reader.lines();
            while let Some(Ok(line)) = lines.next() {
                output.extend_from_slice(line.as_bytes());
                output.push(b'\n');
            }
            output
        });

        let on_stderr = self.on_stderr.take();

        let stderr_thread = std::thread::spawn(move || {
            let mut raw_lines: Vec<u8> = Vec::new();
            let mut ops = Vec::new();

            let mut lines = stderr_reader.lines();
            while let Some(Ok(line)) = lines.next() {
                if let Some(log) = InternalLog::parse(&line).and_then(Result::ok) {
                    if let Some(f) = &on_stderr {
                        f(&log);
                    }

                    if let Some(op) = extract_op_from_log_line(&log) {
                        ops.push(op);
                    }

                    // FIX: verbosity
                    if let Some(msg) = log
                        .filter_by_level(Verbosity::Info)
                        .and_then(InternalLog::get_msg)
                    {
                        raw_lines.extend_from_slice(msg.as_bytes());
                        raw_lines.push(b'\n');
                    }
                }
            }

            (ops, raw_lines)
        });

        let status = child.wait().map_err(CommandError::Io)?;
        let stdout = stdout_thread.join().unwrap();
        let (ops, stderr) = stderr_thread.join().unwrap();

        if !status.success() {
            return Ok(Output {
                status,
                stdout,
                stderr,
                ..Default::default()
            });
        }

        let mut env_inputs = Vec::new();
        let mut sources = Vec::new();

        for op in ops.into_iter() {
            match op {
                Op::CopiedSource { source, .. }
                | Op::EvaluatedFile { source }
                | Op::ReadFile { source }
                | Op::ReadDir { source }
                | Op::PathExists { source }
                | Op::TrackedPath { source }
                    // Filter out paths that don't impact caching
                    if source.starts_with("/")
                        && !source.starts_with("/nix/store")
                        && !self
                            .excluded_paths
                            .iter()
                            .any(|path| source.starts_with(path)) =>
                {
                    sources.push(source);
                }

                Op::GetEnv { name } => {
                    if let Ok(env_input) = EnvInputDesc::new(name) {
                        env_inputs.push(env_input);
                    }
                }

                _ => {}
            }
        }

        // Watch additional paths
        sources.extend_from_slice(&self.extra_paths);

        let file_inputs = query_file_inputs(&sources).await;

        let mut inputs = file_inputs
            .into_iter()
            .map(Input::File)
            .chain(env_inputs.into_iter().map(Input::Env))
            .collect::<Vec<_>>();

        inputs.sort();
        inputs.dedup_by(Input::dedup);

        let input_hash = Input::compute_input_hash(&inputs);

        // Only store results in cache if caching is enabled
        if self.enable_caching {
            let _ = db::insert_command_with_inputs(
                self.pool,
                &raw_cmd,
                &cmd_hash,
                &input_hash,
                &stdout,
                &inputs,
            )
            .await
            .map_err(CommandError::Sqlx)?;
        }

        Ok(Output {
            status,
            stdout,
            stderr,
            inputs,
            cache_hit: false,
            cache_miss_reason,
        })
    }
}

/// Check whether the command supports the flags required for caching.
pub fn supports_eval_caching(cmd: &Command) -> bool {
    cmd.get_program().to_string_lossy().ends_with("nix")
}

/// Reason why the eval cache was not used.
#[derive(Debug, Clone)]
pub enum CacheMissReason {
    /// Command was not found in the cache (first run).
    NotCached,
    /// One or more file inputs were modified.
    FilesModified { paths: Vec<PathBuf> },
    /// One or more file inputs were removed.
    FilesRemoved { paths: Vec<PathBuf> },
    /// One or more environment variables were modified.
    EnvModified { names: Vec<String> },
    /// One or more environment variables were removed.
    EnvRemoved { names: Vec<String> },
    /// The set of tracked inputs changed.
    InputsChanged,
}

impl std::fmt::Display for CacheMissReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCached => write!(f, "first evaluation"),
            Self::FilesModified { paths } => {
                if paths.len() == 1 {
                    write!(f, "{} modified", paths[0].display())
                } else {
                    write!(f, "{} files modified: ", paths.len())?;
                    for (i, path) in paths.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", path.display())?;
                    }
                    Ok(())
                }
            }
            Self::FilesRemoved { paths } => {
                if paths.len() == 1 {
                    write!(f, "{} removed", paths[0].display())
                } else {
                    write!(f, "{} files removed: ", paths.len())?;
                    for (i, path) in paths.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", path.display())?;
                    }
                    Ok(())
                }
            }
            Self::EnvModified { names } => {
                if names.len() == 1 {
                    write!(f, "environment variable {} changed", names[0])
                } else {
                    write!(
                        f,
                        "{} environment variables changed: {}",
                        names.len(),
                        names.join(", ")
                    )
                }
            }
            Self::EnvRemoved { names } => {
                if names.len() == 1 {
                    write!(f, "environment variable {} removed", names[0])
                } else {
                    write!(
                        f,
                        "{} environment variables removed: {}",
                        names.len(),
                        names.join(", ")
                    )
                }
            }
            Self::InputsChanged => write!(f, "tracked inputs changed"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Output {
    /// The status code of the command.
    pub status: process::ExitStatus,
    /// The data that the process wrote to stdout.
    pub stdout: Vec<u8>,
    /// The data that the process wrote to stderr.
    pub stderr: Vec<u8>,
    /// A list of inputs that the command depends on and their hashes.
    pub inputs: Vec<Input>,
    /// Whether the output was returned from the cache or not.
    pub cache_hit: bool,
    /// If cache was missed, the reason why.
    pub cache_miss_reason: Option<CacheMissReason>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Input {
    File(FileInputDesc),
    Env(EnvInputDesc),
}

impl Input {
    pub fn content_hash(&self) -> Option<&str> {
        match self {
            Self::File(desc) => desc.content_hash.as_deref(),
            Self::Env(desc) => desc.content_hash.as_deref(),
        }
    }

    /// Get the identifier for this input (path for files, name for env vars).
    /// Used to compare inputs by identity rather than content.
    pub fn identifier(&self) -> InputIdentifier {
        match self {
            Self::File(desc) => InputIdentifier::File(desc.path.clone()),
            Self::Env(desc) => InputIdentifier::Env(desc.name.clone()),
        }
    }

    pub fn compute_input_hash(inputs: &[Self]) -> String {
        compute_string_hash(
            &inputs
                .iter()
                .filter_map(Input::content_hash)
                .collect::<String>(),
        )
    }

    pub fn partition_refs(inputs: &[Self]) -> (Vec<&FileInputDesc>, Vec<&EnvInputDesc>) {
        let mut file_inputs = Vec::new();
        let mut env_inputs = Vec::new();

        for input in inputs {
            match input {
                Self::File(desc) => file_inputs.push(desc),
                Self::Env(desc) => env_inputs.push(desc),
            }
        }

        (file_inputs, env_inputs)
    }

    pub fn dedup(a: &mut Self, b: &mut Self) -> bool {
        match (a, b) {
            (Input::File(f), Input::File(g)) => {
                f == g
                    || f.path == g.path
                        && f.content_hash == g.content_hash
                        && f.is_directory == g.is_directory
            }
            (Self::Env(f), Self::Env(g)) => f == g,
            _ => false,
        }
    }
}

/// Identifier for an input, used for comparing inputs by path/name rather than content.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum InputIdentifier {
    File(PathBuf),
    Env(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FileInputDesc {
    pub path: PathBuf,
    pub is_directory: bool,
    pub content_hash: Option<String>,
    pub modified_at: SystemTime,
}

impl Ord for FileInputDesc {
    /// Sort by path first, then by modified_at in reverse order.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.path.cmp(&other.path) {
            std::cmp::Ordering::Equal => other.modified_at.cmp(&self.modified_at),
            otherwise => otherwise,
        }
    }
}

impl PartialOrd for FileInputDesc {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl FileInputDesc {
    // A fallback system time is required for paths that don't exist.
    // This avoids duplicate entries for paths that don't exist and would only differ in terms of
    // the timestamp of when this function was called.
    //
    // All timestamps are truncated to second precision.
    pub fn new(path: PathBuf, fallback_system_time: SystemTime) -> Result<Self, io::Error> {
        let is_directory = path.is_dir();
        let content_hash = if is_directory {
            let paths = std::fs::read_dir(&path)?
                .filter_map(Result::ok)
                .map(|entry| entry.path().to_string_lossy().to_string())
                .collect::<String>();
            Some(compute_string_hash(&paths))
        } else {
            compute_file_hash(&path)
                .map_err(|e| std::io::Error::other(format!("Failed to compute file hash: {e}")))
                .ok()
        };
        let modified_at = truncate_to_seconds(
            path.metadata()
                .and_then(|p| p.modified())
                .unwrap_or(fallback_system_time),
        )?;
        Ok(Self {
            path,
            is_directory,
            content_hash,
            modified_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EnvInputDesc {
    pub name: String,
    pub content_hash: Option<String>,
}

impl Ord for EnvInputDesc {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for EnvInputDesc {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl EnvInputDesc {
    pub fn new(name: String) -> Result<Self, io::Error> {
        let value = std::env::var(&name).ok();
        let content_hash = value.map(|v| compute_string_hash(&v));
        Ok(Self { name, content_hash })
    }
}

impl From<db::FileInputRow> for Input {
    fn from(row: db::FileInputRow) -> Self {
        Self::File(row.into())
    }
}

impl From<db::EnvInputRow> for Input {
    fn from(row: db::EnvInputRow) -> Self {
        Self::Env(row.into())
    }
}

impl From<db::FileInputRow> for FileInputDesc {
    fn from(row: db::FileInputRow) -> Self {
        Self {
            path: row.path,
            is_directory: row.is_directory,
            content_hash: if row.content_hash.is_empty() {
                None
            } else {
                Some(row.content_hash)
            },
            modified_at: row.modified_at,
        }
    }
}

impl From<db::EnvInputRow> for EnvInputDesc {
    fn from(row: db::EnvInputRow) -> Self {
        Self {
            name: row.name,
            content_hash: if row.content_hash.is_empty() {
                None
            } else {
                Some(row.content_hash)
            },
        }
    }
}

/// Result from checking the cache - either a hit with output, or a miss with a reason.
enum CacheCheckResult {
    Hit(Output),
    Miss(CacheMissReason),
}

/// Try to fetch the cached output for a hashed command.
///
/// Returns the cached output if the command has been cached and none of the file dependencies have
/// been updated.
async fn query_cached_output(
    pool: &SqlitePool,
    cmd_hash: &str,
    raw_cmd: &str,
    extra_paths: &[PathBuf],
) -> Result<CacheCheckResult, CommandError> {
    let cached_cmd = db::get_command_by_hash(pool, cmd_hash)
        .await
        .map_err(CommandError::Sqlx)?;

    let Some(cmd) = cached_cmd else {
        trace!(cmd = %raw_cmd, "cache miss: not cached");
        return Ok(CacheCheckResult::Miss(CacheMissReason::NotCached));
    };

    trace!(cmd = %raw_cmd, "found cached command, checking inputs");

    let files = db::get_files_by_command_id(pool, cmd.id)
        .await
        .map_err(CommandError::Sqlx)?;
    let envs = db::get_envs_by_command_id(pool, cmd.id)
        .await
        .map_err(CommandError::Sqlx)?;

    let old_inputs: Vec<Input> = files
        .into_iter()
        .map(Input::from)
        .chain(envs.into_iter().map(Input::from))
        .collect();

    let extra_file_inputs = query_file_inputs(extra_paths).await;
    let mut inputs: Vec<Input> = old_inputs.clone();
    inputs.extend(extra_file_inputs.into_iter().map(Input::File));
    inputs.sort();
    inputs.dedup_by(Input::dedup);

    let new_input_hash = Input::compute_input_hash(&inputs);

    // Check if the set of tracked inputs changed
    if cmd.input_hash != new_input_hash {
        debug!(
            cmd = %raw_cmd,
            old_hash = %cmd.input_hash,
            new_hash = %new_input_hash,
            "cache miss: input hash mismatch"
        );

        // Compare by identifier to find added/removed inputs
        let old_ids: std::collections::HashSet<_> =
            old_inputs.iter().map(|i| i.identifier()).collect();
        let new_ids: std::collections::HashSet<_> = inputs.iter().map(|i| i.identifier()).collect();

        let mut added_files = Vec::new();
        let mut added_envs = Vec::new();
        for added_id in new_ids.difference(&old_ids) {
            match added_id {
                InputIdentifier::File(path) => {
                    debug!(cmd = %raw_cmd, path = ?path, "cache miss: new file tracked");
                    added_files.push(path.clone());
                }
                InputIdentifier::Env(name) => {
                    debug!(cmd = %raw_cmd, name = %name, "cache miss: new env var tracked");
                    added_envs.push(name.clone());
                }
            }
        }

        let mut removed_files = Vec::new();
        let mut removed_envs = Vec::new();
        for removed_id in old_ids.difference(&new_ids) {
            match removed_id {
                InputIdentifier::File(path) => {
                    debug!(cmd = %raw_cmd, path = ?path, "cache miss: file no longer tracked");
                    removed_files.push(path.clone());
                }
                InputIdentifier::Env(name) => {
                    debug!(cmd = %raw_cmd, name = %name, "cache miss: env var no longer tracked");
                    removed_envs.push(name.clone());
                }
            }
        }

        // Check for modified inputs (same identifier, different hash)
        let mut modified_files = Vec::new();
        let mut modified_envs = Vec::new();
        let old_map: std::collections::HashMap<_, _> = old_inputs
            .iter()
            .map(|i| (i.identifier(), i.content_hash()))
            .collect();
        let new_map: std::collections::HashMap<_, _> = inputs
            .iter()
            .map(|i| (i.identifier(), i.content_hash()))
            .collect();

        debug!(
            cmd = %raw_cmd,
            old_count = old_map.len(),
            new_count = new_map.len(),
            "comparing input hashes"
        );

        for (id, new_hash) in &new_map {
            if let Some(old_hash) = old_map.get(id) {
                if old_hash != new_hash {
                    match id {
                        InputIdentifier::File(path) => {
                            debug!(
                                cmd = %raw_cmd,
                                path = ?path,
                                old_hash = ?old_hash,
                                new_hash = ?new_hash,
                                "cache miss: file content changed"
                            );
                            modified_files.push(path.clone());
                        }
                        InputIdentifier::Env(name) => {
                            debug!(
                                cmd = %raw_cmd,
                                name = %name,
                                old_hash = ?old_hash,
                                new_hash = ?new_hash,
                                "cache miss: env var content changed"
                            );
                            modified_envs.push(name.clone());
                        }
                    }
                }
            }
        }

        // Return the most relevant reason
        if !modified_files.is_empty() {
            return Ok(CacheCheckResult::Miss(CacheMissReason::FilesModified {
                paths: modified_files,
            }));
        }
        if !added_files.is_empty() {
            return Ok(CacheCheckResult::Miss(CacheMissReason::FilesModified {
                paths: added_files,
            }));
        }
        if !removed_files.is_empty() {
            return Ok(CacheCheckResult::Miss(CacheMissReason::FilesRemoved {
                paths: removed_files,
            }));
        }
        if !modified_envs.is_empty() {
            return Ok(CacheCheckResult::Miss(CacheMissReason::EnvModified {
                names: modified_envs,
            }));
        }
        if !added_envs.is_empty() {
            return Ok(CacheCheckResult::Miss(CacheMissReason::EnvModified {
                names: added_envs,
            }));
        }
        if !removed_envs.is_empty() {
            return Ok(CacheCheckResult::Miss(CacheMissReason::EnvRemoved {
                names: removed_envs,
            }));
        }

        // Otherwise, hash changed but we couldn't identify the specific input
        return Ok(CacheCheckResult::Miss(CacheMissReason::InputsChanged));
    }

    let inputs = Arc::new(inputs);

    // Check each input for modifications
    let mut set = tokio::task::JoinSet::new();
    for (index, _) in inputs.iter().enumerate() {
        let inputs = Arc::clone(&inputs);
        set.spawn_blocking(move || {
            let state = match &inputs[index] {
                Input::File(file) => check_file_state(file),
                Input::Env(env) => check_env_state(env),
            };
            (index, state)
        });
    }

    let mut modified_files = Vec::new();
    let mut modified_envs = Vec::new();
    let mut removed_files = Vec::new();
    let mut removed_envs = Vec::new();

    while let Some(res) = set.join_next().await {
        let Ok((index, Ok(file_state))) = res else {
            continue;
        };

        match file_state {
            FileState::MetadataModified { modified_at } => {
                // mtime changed but content is the same - update the cached mtime
                if let Input::File(file) = &inputs[index] {
                    trace!(cmd = %raw_cmd, path = ?file.path, "mtime changed, content unchanged");
                    db::update_file_modified_at(pool, &file.path, modified_at)
                        .await
                        .map_err(CommandError::Sqlx)?;
                }
            }
            FileState::Modified { .. } => match &inputs[index] {
                Input::File(file) => {
                    debug!(cmd = %raw_cmd, path = ?file.path, "cache miss: file modified");
                    modified_files.push(file.path.clone());
                }
                Input::Env(env) => {
                    debug!(cmd = %raw_cmd, name = %env.name, "cache miss: env modified");
                    modified_envs.push(env.name.clone());
                }
            },
            FileState::Removed => match &inputs[index] {
                Input::File(file) => {
                    debug!(cmd = %raw_cmd, path = ?file.path, "cache miss: file removed");
                    removed_files.push(file.path.clone());
                }
                Input::Env(env) => {
                    debug!(cmd = %raw_cmd, name = %env.name, "cache miss: env removed");
                    removed_envs.push(env.name.clone());
                }
            },
            FileState::Unchanged => {}
        }
    }

    // Return the most relevant reason for cache miss
    if !modified_files.is_empty() {
        return Ok(CacheCheckResult::Miss(CacheMissReason::FilesModified {
            paths: modified_files,
        }));
    }
    if !removed_files.is_empty() {
        return Ok(CacheCheckResult::Miss(CacheMissReason::FilesRemoved {
            paths: removed_files,
        }));
    }
    if !modified_envs.is_empty() {
        return Ok(CacheCheckResult::Miss(CacheMissReason::EnvModified {
            names: modified_envs,
        }));
    }
    if !removed_envs.is_empty() {
        return Ok(CacheCheckResult::Miss(CacheMissReason::EnvRemoved {
            names: removed_envs,
        }));
    }

    trace!(cmd = %raw_cmd, "cache hit");

    db::update_command_updated_at(pool, cmd.id)
        .await
        .map_err(CommandError::Sqlx)?;

    Ok(CacheCheckResult::Hit(Output {
        status: process::ExitStatus::default(),
        stdout: cmd.output,
        stderr: Vec::new(),
        inputs: Arc::try_unwrap(inputs).unwrap_or_else(|arc| (*arc).clone()),
        cache_hit: true,
        cache_miss_reason: None,
    }))
}

async fn query_file_inputs(sources: &[PathBuf]) -> Vec<FileInputDesc> {
    let now = SystemTime::now();
    let file_input_futures = sources
        .iter()
        .cloned()
        .map(|source| {
            tokio::task::spawn_blocking(move || {
                FileInputDesc::new(source, now).map_err(CommandError::Io)
            })
        })
        .collect::<futures::stream::FuturesUnordered<_>>();

    join_all(file_input_futures)
        .await
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .collect::<Vec<_>>()
}

/// Convert a parse log line into into an `Op`.
fn extract_op_from_log_line(log: &InternalLog) -> Option<Op> {
    match log {
        InternalLog::Msg { .. } => Op::from_internal_log(log),
        _ => None,
    }
}

/// Represents the various states of "modified" that we care about.
#[derive(Debug)]
#[allow(dead_code)]
enum FileState {
    /// The file has not been modified since it was last cached.
    Unchanged,
    /// The file's metadata, i.e. timestamp, has changed, but its content remains the same.
    MetadataModified { modified_at: SystemTime },
    /// The file's contents have been modified.
    Modified {
        new_hash: String,
        modified_at: SystemTime,
    },
    /// The file no longer exists in the file system.
    Removed,
}

fn check_file_state(file: &FileInputDesc) -> io::Result<FileState> {
    let metadata = match std::fs::metadata(&file.path) {
        Ok(metadata) => metadata,
        Err(_) => {
            if file.content_hash.is_some() {
                return Ok(FileState::Removed);
            } else {
                return Ok(FileState::Unchanged);
            }
        }
    };

    let modified_at = metadata.modified().and_then(truncate_to_seconds)?;
    if modified_at == file.modified_at {
        // File has not been modified
        return Ok(FileState::Unchanged);
    }

    // mtime has changed, check if content has changed
    let new_hash = if file.is_directory {
        if !metadata.is_dir() {
            return Ok(FileState::Removed);
        }

        let paths = std::fs::read_dir(&file.path)?
            .filter_map(Result::ok)
            .map(|entry| entry.path().to_string_lossy().to_string())
            .collect::<String>();
        compute_string_hash(&paths)
    } else {
        compute_file_hash(&file.path)
            .map_err(|e| std::io::Error::other(format!("Failed to compute file hash: {e}")))?
    };

    if Some(&new_hash) == file.content_hash.as_ref() {
        // File touched but hash unchanged
        Ok(FileState::MetadataModified { modified_at })
    } else {
        // Hash has changed, return new hash
        Ok(FileState::Modified {
            new_hash,
            modified_at,
        })
    }
}

fn check_env_state(env: &EnvInputDesc) -> io::Result<FileState> {
    let value = std::env::var(&env.name);

    if let Err(std::env::VarError::NotPresent) = value {
        if env.content_hash.is_none() {
            return Ok(FileState::Unchanged);
        } else {
            return Ok(FileState::Removed);
        }
    }

    let new_hash = compute_string_hash(&value.unwrap_or("".into()));

    if Some(&new_hash) != env.content_hash.as_ref() {
        Ok(FileState::Modified {
            new_hash,
            modified_at: truncate_to_seconds(SystemTime::now())?,
        })
    } else {
        Ok(FileState::Unchanged)
    }
}

fn truncate_to_seconds(time: SystemTime) -> io::Result<SystemTime> {
    let duration_since_epoch = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("SystemTime before UNIX EPOCH"))?;
    let seconds = duration_since_epoch.as_secs();
    Ok(UNIX_EPOCH + std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_file_row(dir: &TempDir, content: &[u8]) -> db::FileInputRow {
        let file_path = dir.path().join("test_file.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(content).unwrap();

        let metadata = file_path.metadata().unwrap();
        let modified_at = metadata.modified().unwrap();
        let truncated_modified_at = truncate_to_seconds(modified_at).unwrap();
        let content_hash = compute_file_hash(&file_path)
            .map_err(|e| std::io::Error::other(format!("Failed to compute file hash: {e}")))
            .unwrap();

        db::FileInputRow {
            path: file_path,
            is_directory: false,
            content_hash,
            modified_at: truncated_modified_at,
            updated_at: truncated_modified_at,
        }
    }

    #[test]
    fn test_unchanged_file() {
        let temp_dir = TempDir::with_prefix("test_unchanged_file").unwrap();
        let file_row = create_file_row(&temp_dir, b"Hello, World!");

        assert!(matches!(
            check_file_state(&file_row.into()),
            Ok(FileState::Unchanged)
        ));
    }

    #[test]
    fn test_metadata_modified_file() {
        let temp_dir = TempDir::with_prefix("test_metadata_modified_file").unwrap();
        let file_row = create_file_row(&temp_dir, b"Hello, World!");

        // Update the file's timestamp to ensure it's different
        let new_time = SystemTime::now() + std::time::Duration::from_secs(1);
        let file = File::open(&file_row.path).unwrap();
        file.set_modified(new_time).unwrap();
        drop(file);

        assert!(matches!(
            check_file_state(&file_row.into()),
            Ok(FileState::MetadataModified { .. })
        ));
    }

    #[test]
    fn test_content_modified_file() {
        let temp_dir = TempDir::with_prefix("test_content_modified_file").unwrap();
        let file_row = create_file_row(&temp_dir, b"Hello, World!");

        // Modify the file contents
        let mut file = File::create(&file_row.path).unwrap();
        file.write_all(b"Modified content").unwrap();

        // Set mtime to ensure it's different from original
        let new_time = SystemTime::now() + std::time::Duration::from_secs(1);
        file.set_modified(new_time).unwrap();

        assert!(matches!(
            check_file_state(&file_row.into()),
            Ok(FileState::Modified { .. })
        ));
    }

    #[test]
    fn test_removed_file() {
        let temp_dir = TempDir::with_prefix("test_removed_file").unwrap();
        let file_row = create_file_row(&temp_dir, b"Hello, World!");

        // Remove the file
        std::fs::remove_file(&file_row.path).unwrap();

        assert!(matches!(
            check_file_state(&file_row.into()),
            Ok(FileState::Removed)
        ));
    }

    #[test]
    fn test_input_dedup_by() {
        let path = PathBuf::from("test.txt");
        let content_hash = Some("abc123".to_string());
        let file1 = Input::File(FileInputDesc {
            path: path.clone(),
            is_directory: false,
            content_hash: content_hash.clone(),
            modified_at: UNIX_EPOCH,
        });
        let file2 = Input::File(FileInputDesc {
            path: path.clone(),
            is_directory: false,
            content_hash: content_hash.clone(),
            modified_at: UNIX_EPOCH + std::time::Duration::from_secs(1),
        });

        let mut inputs = vec![file1, file2.clone()];
        inputs.sort();
        inputs.dedup_by(Input::dedup);
        assert!(inputs.len() == 1);
        assert_eq!(inputs[0], file2);
    }

    #[test]
    fn test_truncate_system_time_to_seconds() {
        let time = SystemTime::now();
        let truncated_time = truncate_to_seconds(time).unwrap();
        let duration_since_epoch = truncated_time
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_millis();
        // Test that the last 3 digits are zeros
        assert_eq!(duration_since_epoch % 1_000, 0);
    }
}
