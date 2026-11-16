use crate::config::parse::Globals;
use crate::engine::Metrics;
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};

pub struct FileJob {
    pub path: PathBuf,
    pub bytes: bytes::Bytes,
    pub sync: bool,
    pub flush_interval: Option<u64>,
}

// cap open files
const MAX_OPEN: usize = 100;

pub fn spawn_worker(
    g: Globals,
    shutdown: watch::Receiver<bool>,
    metrics: Arc<Metrics>,
) -> mpsc::Sender<FileJob> {
    let (tx, mut rx) = mpsc::channel::<FileJob>(10000);
    tokio::spawn(async move {
        let mut files: HashMap<PathBuf, tokio::fs::File> = HashMap::new();
        let mut last_fsync = std::time::Instant::now();
        while let Some(job) = rx.recv().await {
            if *shutdown.borrow() {
                break;
            }
            if !files.contains_key(&job.path) && files.len() >= MAX_OPEN {
                files.clear();
            }
            let entry = files.entry(job.path.clone());
            let f = match entry {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    match open_file(&job.path, &g).await {
                        Ok(f) => e.insert(f),
                        Err(_) => {
                            metrics.file_errors.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                }
            };
            if f.write_all(&job.bytes).await.is_err() {
                metrics.file_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            // rsyslog: fsync throttled ~1s by default; every write when
            // $ActionFileEnableSync; flushInterval overrides the period.
            let now = std::time::Instant::now();
            if job.sync
                || (job.flush_interval.is_none() && now.duration_since(last_fsync).as_secs() >= 1)
            {
                let _ = f.sync_all().await;
                last_fsync = now;
            }
        }
    });
    tx
}

async fn open_file(path: &std::path::Path, g: &Globals) -> std::io::Result<tokio::fs::File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            // O_NOFOLLOW where the platform supports it: a symlinked
            // output is rejected rather than followed (rsyslog
            // followSymlinks=off / strict mode). Failure to open with
            // O_NOFOLLOW surfaces as the write error metric.
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                let _ = std::fs::set_permissions(
                    parent,
                    std::fs::Permissions::from_mode(g.dir_create_mode),
                );
            }
        }
    }
    let mut opts = tokio::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        let um = g.umask.unwrap_or(0);
        opts.mode(g.file_create_mode & !um);
        opts.custom_flags(libc_bits::O_NOFOLLOW);
    }
    let f = opts.open(path).await?;
    create_attrs(path, g);
    Ok(f)
}

mod libc_bits {
    pub const O_NOFOLLOW: i32 = 0o400000; // Linux; macOS differs
}

pub fn create_attrs(path: &std::path::Path, g: &Globals) {
    // best-effort chown (works as root; as dropped user it fails and warns
    // once — creating as the dropped user is the documented fallback)
    if g.file_owner.is_some() || g.file_group.is_some() {
        let uid = g.file_owner.as_deref().and_then(uid_of);
        let gid = g.file_group.as_deref().and_then(gid_of);
        if let (Some(u), Some(gr)) = (uid, gid) {
            if std::os::unix::fs::chown(path, Some(u), Some(gr)).is_err() {
                crate::log::internal_log(
                    4,
                    &format!("chown {} failed (running as non-root)", path.display()),
                );
            }
        }
    }
}

fn uid_of(name: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let n = f.next()?;
        let id: Option<u32> = f.nth(1)?.parse().ok();
        (n == name).then_some(id).flatten()
    })
}

fn gid_of(name: &str) -> Option<u32> {
    let grp = std::fs::read_to_string("/etc/group").ok()?;
    grp.lines().find_map(|l| {
        let mut f = l.split(':');
        let n = f.next()?;
        let id: Option<u32> = f.next()?.parse().ok();
        (n == name).then_some(id).flatten()
    })
}
