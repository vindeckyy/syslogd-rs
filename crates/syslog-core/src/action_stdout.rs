use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};

pub fn spawn_worker(shutdown: watch::Receiver<bool>) -> mpsc::Sender<String> {
    let (tx, mut rx) = mpsc::channel::<String>(10000);
    tokio::spawn(async move {
        let _ = shutdown;
        let mut out = tokio::io::stdout();
        while let Some(text) = rx.recv().await {
            let _ = out.write_all(text.as_bytes()).await;
        }
    });
    tx
}
