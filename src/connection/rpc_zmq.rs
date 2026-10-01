use anyhow::{bail, Context, Result};
use bitcoin::BlockHash;
use crossbeam_channel::{bounded, Receiver, TrySendError};

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::chain::{Chain, NewHeader};
use crate::headerv2::AnyHeader;
use crate::connection::BlockSource;
use crate::metrics::{default_duration_buckets, Histogram, Metrics};
use crate::types::SerBlock;

const MAX_REORG_DEPTH: usize = 1000;

/// Max headers returned per REST call — matches p2p `getheaders` cap.
const HEADER_BATCH_SIZE: usize = 2000;

/// Number of parallel REST connections for block fetching.
const FETCH_CONNECTIONS: usize = 4;

/// Bounded channel depth between fetcher and consumer in `for_blocks`.
const BLOCK_CHANNEL_DEPTH: usize = 10;

struct RestRequestDiag {
    path: String,
    since: Instant,
    stage: &'static str,
}

struct RestRequestGuard(u64);

static REST_DIAG_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static REST_DIAG_ACTIVE: OnceLock<Mutex<HashMap<u64, RestRequestDiag>>> = OnceLock::new();

struct ForBlocksWorkerDiag {
    stage: &'static str,
    since: Instant,
    completed: usize,
    assigned: usize,
}

struct ForBlocksDiag {
    started: Instant,
    phase_started: Instant,
    phase: &'static str,
    total: usize,
    received: usize,
    processed: usize,
    pending: usize,
    workers: HashMap<usize, ForBlocksWorkerDiag>,
}

struct ForBlocksDiagGuard(u64);

static FOR_BLOCKS_DIAG_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static FOR_BLOCKS_DIAG_ACTIVE: OnceLock<Mutex<HashMap<u64, ForBlocksDiag>>> = OnceLock::new();

fn rest_diag() -> &'static Mutex<HashMap<u64, RestRequestDiag>> {
    REST_DIAG_ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn for_blocks_diag() -> &'static Mutex<HashMap<u64, ForBlocksDiag>> {
    FOR_BLOCKS_DIAG_ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

impl ForBlocksDiagGuard {
    fn new(total: usize) -> Self {
        let id = FOR_BLOCKS_DIAG_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        for_blocks_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(
                id,
                ForBlocksDiag {
                    started: now,
                    phase_started: now,
                    phase: "start",
                    total,
                    received: 0,
                    processed: 0,
                    pending: 0,
                    workers: HashMap::new(),
                },
            );
        Self(id)
    }

    fn id(&self) -> u64 {
        self.0
    }

    fn set_phase(&self, phase: &'static str) {
        let mut active = for_blocks_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(entry) = active.get_mut(&self.0) {
            let elapsed = entry.phase_started.elapsed();
            if elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow REST for_blocks phase id={} phase={} elapsed_ms={} total={} received={} processed={} pending={}",
                    self.0,
                    entry.phase,
                    elapsed.as_millis(),
                    entry.total,
                    entry.received,
                    entry.processed,
                    entry.pending,
                );
            }
            entry.phase = phase;
            entry.phase_started = Instant::now();
        }
    }

    fn progress(&self, received: usize, processed: usize, pending: usize) {
        if let Some(entry) = for_blocks_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get_mut(&self.0)
        {
            entry.received = received;
            entry.processed = processed;
            entry.pending = pending;
        }
    }
}

impl Drop for ForBlocksDiagGuard {
    fn drop(&mut self) {
        let entry = for_blocks_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.0);
        if let Some(entry) = entry {
            let elapsed = entry.started.elapsed();
            if elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow REST for_blocks id={} elapsed_ms={} final_phase={} final_phase_ms={} total={} received={} processed={} pending={}",
                    self.0,
                    elapsed.as_millis(),
                    entry.phase,
                    entry.phase_started.elapsed().as_millis(),
                    entry.total,
                    entry.received,
                    entry.processed,
                    entry.pending,
                );
            }
        }
    }
}

fn set_for_blocks_worker_stage(
    call_id: u64,
    worker_id: usize,
    stage: &'static str,
    completed: usize,
    assigned: usize,
) {
    let mut active = for_blocks_diag()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    if let Some(call) = active.get_mut(&call_id) {
        call.workers.insert(
            worker_id,
            ForBlocksWorkerDiag {
                stage,
                since: Instant::now(),
                completed,
                assigned,
            },
        );
    }
}

fn diagnostic_for_blocks_state() -> String {
    let active = for_blocks_diag()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let mut calls: Vec<String> = active
        .iter()
        .map(|(id, call)| {
            let mut workers: Vec<String> = call
                .workers
                .iter()
                .map(|(worker_id, worker)| {
                    format!(
                        "worker={} stage={} stage_ms={} completed={}/{}",
                        worker_id,
                        worker.stage,
                        worker.since.elapsed().as_millis(),
                        worker.completed,
                        worker.assigned,
                    )
                })
                .collect();
            workers.sort();
            format!(
                "id={} total_ms={} phase={} phase_ms={} total={} received={} processed={} pending={} workers=[{}]",
                id,
                call.started.elapsed().as_millis(),
                call.phase,
                call.phase_started.elapsed().as_millis(),
                call.total,
                call.received,
                call.processed,
                call.pending,
                workers.join("; "),
            )
        })
        .collect();
    calls.sort();
    format!("active={} calls=[{}]", active.len(), calls.join("; "))
}

impl RestRequestGuard {
    fn new(path: &str) -> Self {
        let id = REST_DIAG_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        rest_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(
                id,
                RestRequestDiag {
                    path: path.to_owned(),
                    since: Instant::now(),
                    stage: "first-attempt",
                },
            );
        Self(id)
    }

    fn set_stage(&self, stage: &'static str) {
        if let Some(request) = rest_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get_mut(&self.0)
        {
            request.stage = stage;
        }
    }
}

impl Drop for RestRequestGuard {
    fn drop(&mut self) {
        rest_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.0);
    }
}

fn diagnostic_rest_state() -> String {
    let active = rest_diag().lock().unwrap_or_else(|err| err.into_inner());
    let mut requests: Vec<String> = active
        .iter()
        .map(|(id, request)| {
            format!(
                "id={} stage={} elapsed_ms={} path={}",
                id,
                request.stage,
                request.since.elapsed().as_millis(),
                request.path,
            )
        })
        .collect();
    requests.sort();
    if requests.len() > 8 {
        requests.truncate(8);
        requests.push("more-requests-omitted".to_owned());
    }
    format!(
        "active={} requests=[{}] for_blocks={}",
        active.len(),
        requests.join("; "),
        diagnostic_for_blocks_state(),
    )
}

/// Block source backed entirely by the Bitcoin Core REST interface (for
/// headers and blocks) and ZMQ (for new-block notifications).
///
/// No RPC, no authentication. Requires `rest=1` and `zmqpubhashblock=tcp://<bind-address>:<bind-port>` in bitcoin.conf.
pub struct RestZmqBlockSource {
    rest_conn: RestConn,
    block_fetchers: Vec<RestConn>,
    new_block_recv: Receiver<()>,
    blocks_duration: Histogram,
}

impl RestZmqBlockSource {
    pub fn connect(rest_addr: SocketAddr, zmq_endpoint: &str, metrics: &Metrics) -> Result<Self> {
        // Verify REST is enabled.
        let mut conn = RestConn::connect(rest_addr)?;
        conn.get("/rest/chaininfo.json")
            .context("REST not reachable — ensure bitcoind is started with rest=1")?;

        let new_block_recv = spawn_zmq_listener(zmq_endpoint)?;

        let blocks_duration = metrics.histogram_vec(
            "rest_zmq_blocks_duration",
            "Time spent getting blocks via REST (in seconds)",
            "step",
            default_duration_buckets(),
        );

        let mut block_fetchers = Vec::with_capacity(FETCH_CONNECTIONS);
        for _ in 0..FETCH_CONNECTIONS {
            block_fetchers.push(RestConn::connect(rest_addr)?);
        }

        info!(
            "REST+ZMQ block source ready (rest={}, zmq={})",
            rest_addr, zmq_endpoint
        );

        Ok(Self {
            rest_conn: conn,
            block_fetchers,
            new_block_recv,
            blocks_duration,
        })
    }

    /// `/rest/chaininfo.json` → (best block hash, height).
    fn chain_info(&mut self) -> Result<(BlockHash, usize)> {
        let body = self.rest_conn.get("/rest/chaininfo.json")?;
        let v: serde_json::Value =
            serde_json::from_slice(&body).context("invalid chaininfo JSON")?;

        let tip: BlockHash = v["bestblockhash"]
            .as_str()
            .context("missing bestblockhash")?
            .parse()
            .context("invalid bestblockhash")?;
        let height = v["blocks"].as_u64().context("missing blocks")? as usize;
        Ok((tip, height))
    }

    /// `/rest/blockhashbyheight/<h>.json` → block hash at height.
    fn block_hash_at_height(&mut self, height: usize) -> Result<BlockHash> {
        let path = format!("/rest/blockhashbyheight/{}.json", height);
        let body = self.rest_conn.get(&path)?;
        let v: serde_json::Value =
            serde_json::from_slice(&body).context("invalid blockhashbyheight JSON")?;

        v["blockhash"]
            .as_str()
            .context("missing blockhash")?
            .parse()
            .context("invalid blockhash")
    }

    /// `/rest/headers/<count>/<hash>.bin` -> raw v1/v2 headers.
    ///
    /// Returns up to `count` headers starting from **and including** `hash`.
    fn raw_headers(&mut self, hash: &BlockHash, count: usize) -> Result<Vec<AnyHeader>> {
        let path = format!("/rest/headers/{}/{}.bin", count, hash);
        let body = self.rest_conn.get(&path)?;
        AnyHeader::parse_all(&body).context("invalid header stream from REST")
    }

    /// Fetch new headers after our tip in one REST call.
    ///
    /// Gets the hash at local_height+1 via blockhashbyheight, then requests
    /// headers starting from that hash. All returned headers are new.
    /// Validates prev_blockhash continuity to detect races with reorgs.
    fn fetch_headers_after_tip(&mut self, chain: &Chain) -> Result<Vec<NewHeader>> {
        let local_height = chain.height();

        // Get the hash of the first block we don't have.
        let next_hash = self.block_hash_at_height(local_height + 1)?;

        // REST headers include the starting hash, so all returned are new.
        let headers = self.raw_headers(&next_hash, HEADER_BATCH_SIZE)?;

        if headers.is_empty() {
            warn!(
                "[blake2b-diag] REST returned zero headers for existing next_hash={} at height={}",
                next_hash,
                local_height + 1,
            );
            return Ok(vec![]);
        }

        let v1 = headers.iter().filter(|header| !header.is_v2()).count();
        let v2 = headers.len() - v1;
        info!(
            "[blake2b-diag] parsed new header batch start_height={} count={} v1={} v2={} first_hash={} last_hash={}",
            local_height + 1,
            headers.len(),
            v1,
            v2,
            headers[0].block_hash(),
            headers.last().expect("non-empty header batch").block_hash(),
        );

        let first_hash = headers[0].block_hash();
        if first_hash != next_hash {
            error!(
                "[blake2b-diag] HASH MISMATCH at height={}: node_hash={} electrs_hash={} {}",
                local_height + 1,
                next_hash,
                first_hash,
                header_details(&headers[0]),
            );
            log_hash_stages(&headers[0]);
        }

        // Verify the first header connects to our tip.
        if headers[0].prev_blockhash() != chain.tip() {
            bail!(
                "REST header discontinuity: header at height {} has prev_blockhash {}, expected tip {}",
                local_height + 1,
                headers[0].prev_blockhash(),
                chain.tip(),
            );
        }

        // Verify internal continuity.
        for i in 1..headers.len() {
            let expected = headers[i - 1].block_hash();
            if headers[i].prev_blockhash() != expected {
                error!(
                    "[blake2b-diag] LINK MISMATCH height={} prev={} electrs_prev_hash={} current={} previous={}",
                    local_height + i + 1,
                    headers[i].prev_blockhash(),
                    expected,
                    header_details(&headers[i]),
                    header_details(&headers[i - 1]),
                );
                log_hash_stages(&headers[i - 1]);
                bail!(
                    "REST header chain broken at index {}: prev_blockhash {} != expected {}",
                    i,
                    headers[i].prev_blockhash(),
                    expected,
                );
            }
        }

        debug!(
            "got {} new headers via REST (heights {}..={})",
            headers.len(),
            local_height + 1,
            local_height + headers.len(),
        );

        Ok(headers
            .into_iter()
            .zip((local_height + 1)..)
            .map(NewHeader::from)
            .collect())
    }

    /// Reorg slow path: walk backwards from the remote tip until we find a
    /// hash present in our local chain (the fork point).
    fn walk_backwards_for_headers(
        &mut self,
        chain: &Chain,
        remote_tip: BlockHash,
    ) -> Result<Vec<NewHeader>> {
        let mut headers: Vec<AnyHeader> = Vec::new();
        let mut current = remote_tip;

        loop {
            if headers.len() >= MAX_REORG_DEPTH {
                bail!(
                    "reorg deeper than {} blocks — aborting backwards walk",
                    MAX_REORG_DEPTH
                );
            }

            let fetched = self.raw_headers(&current, 1)?;
            let header = fetched
                .into_iter()
                .next()
                .with_context(|| format!("REST: no header for {}", current))?;

            let prev = header.prev_blockhash();
            headers.push(header);

            if let Some(fork_height) = chain.get_block_height(&prev) {
                headers.reverse();
                debug!(
                    "got {} new headers via REST backwards walk (fork at height {})",
                    headers.len(),
                    fork_height,
                );
                return Ok(headers
                    .into_iter()
                    .zip((fork_height + 1)..)
                    .map(NewHeader::from)
                    .collect());
            }
            current = prev;
        }
    }
}

impl BlockSource for RestZmqBlockSource {
    /// Fetch new headers, capped at HEADER_BATCH_SIZE per call.
    ///
    /// Fast path: verify our tip is on the main chain, fetch headers in one
    /// REST call. Slow path (reorg): walk backwards to find fork point.
    fn get_new_headers(&mut self, chain: &Chain) -> Result<Vec<NewHeader>> {
        let (remote_tip, remote_height) = self.chain_info()?;

        // Already at tip.
        if let Some(height) = chain.get_block_height(&remote_tip) {
            if height != remote_height {
                error!(
                    "[blake2b-diag] remote tip is locally known at different height: local_map_height={} remote_height={} hash={}",
                    height,
                    remote_height,
                    remote_tip,
                );
            }
            return Ok(vec![]);
        }

        let local_height = chain.height();

        // Fast path: verify our tip is still on the active chain.
        if local_height <= remote_height {
            let hash_at_ours = self.block_hash_at_height(local_height)?;
            if hash_at_ours == chain.tip() {
                let headers = self.fetch_headers_after_tip(chain)?;
                if local_height + headers.len() == remote_height {
                    if let Some(last) = headers.last() {
                        if last.hash() != remote_tip {
                            error!(
                                "[blake2b-diag] REMOTE TIP HASH MISMATCH height={} node_hash={} electrs_hash={}",
                                remote_height,
                                remote_tip,
                                last.hash(),
                            );
                        }
                    }
                }
                return Ok(headers);
            }
            warn!(
                "[blake2b-diag] active-chain check=MISMATCH height={} node_hash={} electrs_hash={}",
                local_height,
                hash_at_ours,
                chain.tip(),
            );
        }

        // Reorg (or remote behind us) — walk backwards.
        warn!(
            "[blake2b-diag] entering backwards walk local_height={} remote_height={} remote_tip={}",
            local_height,
            remote_height,
            remote_tip,
        );
        self.walk_backwards_for_headers(chain, remote_tip)
    }

    /// Fetch blocks via `/rest/block/<hash>.bin` using multiple parallel
    /// keep-alive connections to eliminate per-block dead time.
    ///
    /// Block hashes are striped across N fetcher threads (each with its own
    /// TCP connection). A reorder buffer ensures blocks arrive at the consumer
    /// in the original requested order.
    fn for_blocks<'a>(
        &'a mut self,
        blockhashes: Vec<BlockHash>,
        mut func: Box<dyn FnMut(BlockHash, SerBlock) + 'a>,
    ) -> Result<()> {
        if blockhashes.is_empty() {
            return Ok(());
        }

        let diag = ForBlocksDiagGuard::new(blockhashes.len());
        diag.set_phase("partition-work");

        debug!(
            "REST: fetching {} blocks ({} connections)",
            blockhashes.len(),
            FETCH_CONNECTIONS
        );

        let blocks_duration = &self.blocks_duration;
        let block_fetchers = &mut self.block_fetchers;

        blocks_duration.observe_duration("total", || {
            // Each fetcher gets (index, hash) pairs so we can reorder.
            let mut work: Vec<Vec<(usize, BlockHash)>> =
                (0..FETCH_CONNECTIONS).map(|_| Vec::new()).collect();
            for (i, hash) in blockhashes.iter().enumerate() {
                work[i % FETCH_CONNECTIONS].push((i, *hash));
            }

            let (tx, rx) = bounded::<(usize, BlockHash, SerBlock)>(BLOCK_CHANNEL_DEPTH);

            std::thread::scope(|s| {
                diag.set_phase("spawn-workers");
                let call_id = diag.id();
                // Spawn fetcher threads, each borrowing a persistent connection.
                let fetchers: Vec<_> = work
                    .into_iter()
                    .zip(block_fetchers.iter_mut())
                    .enumerate()
                    .map(|(conn_id, (assignments, conn))| {
                        let tx = tx.clone();
                        let assigned = assignments.len();
                        set_for_blocks_worker_stage(call_id, conn_id, "starting", 0, assigned);
                        s.spawn(move || {
                            let mut err = None;
                            let mut completed = 0;
                            for (idx, hash) in assignments {
                                set_for_blocks_worker_stage(
                                    call_id,
                                    conn_id,
                                    "rest-get",
                                    completed,
                                    assigned,
                                );
                                let path = format!("/rest/block/{}.bin", hash);
                                match conn.get(&path) {
                                    Ok(block) => {
                                        set_for_blocks_worker_stage(
                                            call_id,
                                            conn_id,
                                            "channel-send",
                                            completed,
                                            assigned,
                                        );
                                        if tx.send((idx, hash, block)).is_err() {
                                            break;
                                        }
                                        completed += 1;
                                    }
                                    Err(e) => {
                                        set_for_blocks_worker_stage(
                                            call_id,
                                            conn_id,
                                            "error",
                                            completed,
                                            assigned,
                                        );
                                        err = Some(e.context(format!(
                                            "REST conn {}: block {}",
                                            conn_id, hash
                                        )));
                                        break;
                                    }
                                }
                            }
                            set_for_blocks_worker_stage(
                                call_id,
                                conn_id,
                                "done",
                                completed,
                                assigned,
                            );
                            err
                        })
                    })
                    .collect();

                // Drop our copy so channel closes when all fetchers finish.
                drop(tx);

                // Reorder buffer: blocks arrive out of order, consumer needs
                // them in sequence.
                let mut next_idx = 0;
                let mut received = 0;
                let mut pending: std::collections::HashMap<usize, (BlockHash, SerBlock)> =
                    std::collections::HashMap::new();

                diag.set_phase("receive-channel");
                for (idx, hash, block) in rx {
                    received += 1;
                    pending.insert(idx, (hash, block));
                    diag.progress(received, next_idx, pending.len());

                    // Flush all consecutive ready blocks.
                    while let Some((h, b)) = pending.remove(&next_idx) {
                        diag.set_phase("process-block");
                        diag.progress(received, next_idx, pending.len());
                        blocks_duration.observe_duration("process", || func(h, b));
                        next_idx += 1;
                        diag.progress(received, next_idx, pending.len());
                        diag.set_phase("receive-channel");
                    }
                }

                // Check for fetcher errors.
                diag.set_phase("join-workers");
                let mut first_err = None;
                for f in fetchers {
                    let err = f.join().expect("fetcher panicked");
                    if first_err.is_none() {
                        first_err = err;
                    }
                }

                if let Some(e) = first_err {
                    return Err(e);
                }

                diag.set_phase("complete");
                assert_eq!(next_idx, blockhashes.len(), "not all blocks were processed");
                Ok(())
            })
        })
    }

    fn new_block_notification(&self) -> Receiver<()> {
        self.new_block_recv.clone()
    }
}

/// Persistent HTTP/1.1 connection to bitcoind REST.
/// Reuses a single TCP stream across requests to avoid per-request overhead.
struct RestConn {
    addr: SocketAddr,
    reader: BufReader<TcpStream>,
}

impl RestConn {
    fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .with_context(|| format!("REST: connect to {} failed", addr))?;
        stream.set_read_timeout(Some(Duration::from_secs(120))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
        let reader = BufReader::new(stream);
        Ok(Self { addr, reader })
    }

    /// GET a path; auto-reconnects once on failure.
    fn get(&mut self, path: &str) -> Result<Vec<u8>> {
        let diag = RestRequestGuard::new(path);
        let started = Instant::now();
        match self.do_get(path) {
            Ok(body) => {
                let elapsed = started.elapsed();
                if elapsed >= Duration::from_secs(10) {
                    warn!(
                        "[blake2b-diag] slow REST GET path={} bytes={} elapsed_ms={}",
                        path,
                        body.len(),
                        elapsed.as_millis(),
                    );
                }
                Ok(body)
            }
            Err(first_err) => {
                warn!(
                    "[blake2b-diag] REST GET retry path={} elapsed_ms={} first_error={:#}",
                    path,
                    started.elapsed().as_millis(),
                    first_err,
                );
                diag.set_stage("reconnect");
                *self = Self::connect(self.addr)?;
                diag.set_stage("retry");
                let retry_started = Instant::now();
                let result = self.do_get(path);
                match &result {
                    Ok(body) => warn!(
                        "[blake2b-diag] REST GET retry succeeded path={} bytes={} elapsed_ms={}",
                        path,
                        body.len(),
                        retry_started.elapsed().as_millis(),
                    ),
                    Err(err) => error!(
                        "[blake2b-diag] REST GET retry failed path={} elapsed_ms={} error={:#}",
                        path,
                        retry_started.elapsed().as_millis(),
                        err,
                    ),
                }
                result
            }
        }
    }

    fn do_get(&mut self, path: &str) -> Result<Vec<u8>> {
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAccept-Encoding: identity\r\n\r\n",
            path, self.addr
        );
        self.reader
            .get_mut()
            .write_all(req.as_bytes())
            .context("REST: write failed")?;

        let mut status = String::new();
        let n = self
            .reader
            .read_line(&mut status)
            .context("REST: read status")?;
        if n == 0 {
            bail!("REST: connection closed (EOF reading status)");
        }
        let status_code = status
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .with_context(|| format!("REST: malformed status line: {}", status.trim()))?;
        let is_ok = status_code == 200;

        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .context("REST: read header")?;
            if n == 0 {
                bail!("REST: connection closed (EOF reading headers)");
            }
            let t = line.trim();
            if t.is_empty() {
                break;
            }
            let lower = t.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().ok();
            }
            if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                chunked = true;
            }
        }

        let body = if let Some(len) = content_length {
            let mut body = vec![0u8; len];
            self.reader
                .read_exact(&mut body)
                .context("REST: read body")?;
            body
        } else if chunked {
            self.read_chunked()?
        } else if !is_ok {
            // Unknown body framing on error response — connection is
            // potentially desynced. Force reconnect on next request.
            *self = Self::connect(self.addr)?;
            Vec::new()
        } else {
            bail!("REST: no Content-Length and not chunked");
        };

        if !is_ok {
            bail!("REST: {} → {} {}", path, status_code, status.trim());
        }

        Ok(body)
    }

    fn read_chunked(&mut self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line)?;
            // Strip chunk extensions (e.g. "1a;foo=bar" → "1a").
            let hex = line.trim().split(';').next().unwrap_or("0");
            let size = usize::from_str_radix(hex, 16).context("bad chunk size")?;
            if size == 0 {
                // Drain trailers: read until empty line.
                loop {
                    let mut trailer = String::new();
                    self.reader.read_line(&mut trailer)?;
                    if trailer.trim().is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0u8; size];
            self.reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            self.reader.read_exact(&mut crlf)?;
        }
        Ok(body)
    }
}

fn spawn_zmq_listener(endpoint: &str) -> Result<Receiver<()>> {
    let ctx = zmq::Context::new();
    let sub = ctx.socket(zmq::SUB).context("ZMQ: create socket")?;
    sub.connect(endpoint)
        .with_context(|| format!("ZMQ: connect to {}", endpoint))?;
    sub.set_subscribe(b"hashblock").context("ZMQ: subscribe")?;

    info!("subscribed to ZMQ hashblock at {}", endpoint);

    let (tx, rx) = bounded::<()>(0);
    let ep = endpoint.to_owned();

    crate::thread::spawn("zmq_listener", move || loop {
        let topic = match sub.recv_bytes(0) {
            Ok(topic) => topic,
            Err(zmq::Error::ETERM) => {
                debug!("ZMQ terminated");
                return Ok(());
            }
            Err(e) => bail!("ZMQ recv on {}: {}", ep, e),
        };
        let mut frames = Vec::new();
        while sub.get_rcvmore().unwrap_or(false) {
            match sub.recv_bytes(0) {
                Ok(frame) => frames.push(frame),
                Err(e) => {
                    warn!("[blake2b-diag] ZMQ multipart recv error endpoint={} error={}", ep, e);
                    break;
                }
            }
        }
        let payload_hex = frames
            .first()
            .map(|frame| bytes_hex(frame))
            .unwrap_or_default();
        match tx.try_send(()) {
            Ok(()) => info!(
                "[blake2b-diag] ZMQ block wakeup queued topic={} hash_raw={}",
                String::from_utf8_lossy(&topic),
                payload_hex,
            ),
            Err(TrySendError::Full(())) => warn!(
                "[blake2b-diag] ZMQ block wakeup DROPPED reason=receiver-not-ready topic={} hash_raw={} server_state={} rest_state={}",
                String::from_utf8_lossy(&topic),
                payload_hex,
                crate::server::diagnostic_server_state(),
                diagnostic_rest_state(),
            ),
            Err(TrySendError::Disconnected(())) => {
                error!(
                    "[blake2b-diag] ZMQ block wakeup lost reason=receiver-disconnected endpoint={} topic={} hash_raw={}",
                    ep,
                    String::from_utf8_lossy(&topic),
                    payload_hex,
                );
                return Ok(());
            }
        }
    });

    Ok(rx)
}

fn header_details(header: &AnyHeader) -> String {
    match header {
        AnyHeader::V1(_) => "kind=v1".to_owned(),
        AnyHeader::V2(h) => format!(
            "kind=v2 profile={} flags=0x{:02x} header_height={} time_on_wire={} time_offset={} txcount={} xor_clear_bits={} xor_key_nonzero={}",
            h.asic_profile(),
            h.flags,
            h.height,
            h.time_on_wire,
            h.time_offset,
            h.txcount,
            h.xor_key_mask_clear_bits,
            h.xor_key.iter().any(|b| *b != 0),
        ),
    }
}

fn bytes_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn log_hash_stages(header: &AnyHeader) {
    let AnyHeader::V2(h) = header else {
        return;
    };
    let s = h.stages();
    error!(
        "[blake2b-diag] stages xor_key_hash={} mask={} h1={} h2={} blake2b_1={} blake2b_2={} final_internal={} asic_len={}",
        bytes_hex(&s.xor_key_hash),
        bytes_hex(&s.mask),
        bytes_hex(&s.h1),
        bytes_hex(&s.h2),
        bytes_hex(&s.blake2b_1),
        bytes_hex(&s.blake2b_2),
        bytes_hex(&s.block_hash),
        s.asic_input.len(),
    );
}
