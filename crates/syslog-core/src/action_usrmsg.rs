use crate::engine::Metrics;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};

pub fn spawn_worker(
    shutdown: watch::Receiver<bool>,
    _metrics: Arc<Metrics>,
) -> mpsc::Sender<String> {
    let (tx, mut rx) = mpsc::channel::<String>(10000);
    tokio::spawn(async move {
        let _ = shutdown;
        while let Some(text) = rx.recv().await {
            let mut cmd = tokio::process::Command::new("/usr/bin/wall");
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Ok(mut child) = cmd.spawn() {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes()).await;
                }
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
            }
        }
    });
    tx
}
