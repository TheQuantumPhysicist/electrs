use bitcoin::Txid;
use parking_lot::RwLock;

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex as StdMutex, OnceLock,
};
use std::time::{Duration, Instant};

use crate::metrics::{self, Histogram, Metrics};

pub(crate) struct Cache {
    txs: Arc<RwLock<HashMap<Txid, Box<[u8]>>>>,

    // stats
    txs_size: Histogram,
}

struct CacheWaitDiagEntry {
    since: Instant,
    kind: &'static str,
}

static CACHE_WAIT_DIAG_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static CACHE_WAIT_DIAG: OnceLock<StdMutex<HashMap<u64, CacheWaitDiagEntry>>> = OnceLock::new();

fn cache_wait_diag() -> &'static StdMutex<HashMap<u64, CacheWaitDiagEntry>> {
    CACHE_WAIT_DIAG.get_or_init(|| StdMutex::new(HashMap::new()))
}

pub(crate) fn diagnostic_cache_state() -> String {
    let active = cache_wait_diag()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let mut entries: Vec<String> = active
        .iter()
        .map(|(id, entry)| {
            format!(
                "id={} kind={} elapsed_ms={}",
                id,
                entry.kind,
                entry.since.elapsed().as_millis(),
            )
        })
        .collect();
    entries.sort();
    if entries.len() > 8 {
        entries.truncate(8);
        entries.push("more-cache-waiters-omitted".to_owned());
    }
    format!("active={} waiters=[{}]", active.len(), entries.join("; "))
}

struct CacheWaitDiagGuard {
    id: u64,
}

impl CacheWaitDiagGuard {
    fn new(kind: &'static str) -> Self {
        let id = CACHE_WAIT_DIAG_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        cache_wait_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(
                id,
                CacheWaitDiagEntry {
                    since: Instant::now(),
                    kind,
                },
            );
        Self { id }
    }
}

impl Drop for CacheWaitDiagGuard {
    fn drop(&mut self) {
        let entry = cache_wait_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.id);
        if let Some(entry) = entry {
            let elapsed = entry.since.elapsed();
            if elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow cache lock wait kind={} elapsed_ms={}",
                    entry.kind,
                    elapsed.as_millis(),
                );
            }
        }
    }
}

impl Cache {
    pub fn new(metrics: &Metrics) -> Self {
        Cache {
            txs: Default::default(),
            txs_size: metrics.histogram_vec(
                "cache_txs_size",
                "Cached transactions' size (in bytes)",
                "type",
                metrics::default_size_buckets(),
            ),
        }
    }

    pub fn add_tx(&self, txid: Txid, f: impl FnOnce() -> Box<[u8]>) {
        let mut txs = match self.txs.try_write() {
            Some(txs) => txs,
            None => {
                let wait = CacheWaitDiagGuard::new("write");
                let txs = self.txs.write();
                drop(wait);
                txs
            }
        };
        txs.entry(txid).or_insert_with(|| {
            let tx = f();
            self.txs_size.observe("serialized", tx.len() as f64);
            tx
        });
    }

    pub fn get_tx<F, T>(&self, txid: &Txid, f: F) -> Option<T>
    where
        F: FnOnce(&[u8]) -> T,
    {
        let txs = match self.txs.try_read() {
            Some(txs) => txs,
            None => {
                let wait = CacheWaitDiagGuard::new("read");
                let txs = self.txs.read();
                drop(wait);
                txs
            }
        };
        txs.get(txid).map(|tx_bytes| f(tx_bytes))
    }
}
