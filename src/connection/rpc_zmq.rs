use anyhow::{bail, Context, Result};
use bitcoin::BlockHash;
use crossbeam_channel::{bounded, Receiver};

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
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
        let started = Instant::now();
        let body = self.rest_conn.get("/rest/chaininfo.json")?;
        let v: serde_json::Value =
            serde_json::from_slice(&body).context("invalid chaininfo JSON")?;

        let tip: BlockHash = v["bestblockhash"]
            .as_str()
            .context("missing bestblockhash")?
            .parse()
            .context("invalid bestblockhash")?;
        let height = v["blocks"].as_u64().context("missing blocks")? as usize;
        let header_height = v["headers"].as_u64();
        info!(
            "[blake2b-diag] REST chaininfo blocks={} headers={:?} remote_tip={} elapsed_ms={}",
            height,
            header_height,
            tip,
            started.elapsed().as_millis(),
        );
        Ok((tip, height))
    }

    /// `/rest/blockhashbyheight/<h>.json` → block hash at height.
    fn block_hash_at_height(&mut self, height: usize) -> Result<BlockHash> {
        let started = Instant::now();
        let path = format!("/rest/blockhashbyheight/{}.json", height);
        let body = self.rest_conn.get(&path)?;
        let v: serde_json::Value =
            serde_json::from_slice(&body).context("invalid blockhashbyheight JSON")?;

        let hash = v["blockhash"]
            .as_str()
            .context("missing blockhash")?
            .parse()
            .context("invalid blockhash")?;
        info!(
            "[blake2b-diag] blockhashbyheight height={} hash={} elapsed_ms={}",
            height,
            hash,
            started.elapsed().as_millis(),
        );
        Ok(hash)
    }

    /// `/rest/headers/<count>/<hash>.bin` -> raw v1/v2 headers.
    ///
    /// Returns up to `count` headers starting from **and including** `hash`.
    fn raw_headers(&mut self, hash: &BlockHash, count: usize) -> Result<Vec<AnyHeader>> {
        let started = Instant::now();
        let path = format!("/rest/headers/{}/{}.bin", count, hash);
        let body = self.rest_conn.get(&path)?;
        let headers = AnyHeader::parse_all(&body).context("invalid header stream from REST")?;
        let v1 = headers.iter().filter(|h| !h.is_v2()).count();
        let v2 = headers.len() - v1;
        info!(
            "[blake2b-diag] headers start_hash={} requested={} bytes={} parsed={} v1={} v2={} elapsed_ms={}",
            hash,
            count,
            body.len(),
            headers.len(),
            v1,
            v2,
            started.elapsed().as_millis(),
        );
        Ok(headers)
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
        } else {
            info!(
                "[blake2b-diag] first header hash verified height={} hash={} {}",
                local_height + 1,
                first_hash,
                header_details(&headers[0]),
            );
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
        info!(
            "[blake2b-diag] sync probe local_height={} local_tip={} local_tip_kind={}",
            chain.height(),
            chain.tip(),
            chain
                .get_block_header(chain.height())
                .map(header_kind)
                .unwrap_or("missing"),
        );
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
            info!(
                "[blake2b-diag] sync result=already-known remote_tip_height={} remote_height={}",
                height,
                remote_height,
            );
            return Ok(vec![]);
        }

        let local_height = chain.height();

        // Fast path: verify our tip is still on the active chain.
        if local_height <= remote_height {
            let hash_at_ours = self.block_hash_at_height(local_height)?;
            if hash_at_ours == chain.tip() {
                info!(
                    "[blake2b-diag] active-chain check=match height={} hash={}",
                    local_height,
                    hash_at_ours,
                );
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
                        } else {
                            info!(
                                "[blake2b-diag] remote tip hash verified height={} hash={}",
                                remote_height,
                                remote_tip,
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
                // Spawn fetcher threads, each borrowing a persistent connection.
                let fetchers: Vec<_> = work
                    .into_iter()
                    .zip(block_fetchers.iter_mut())
                    .enumerate()
                    .map(|(conn_id, (assignments, conn))| {
                        let tx = tx.clone();
                        s.spawn(move || {
                            let mut err = None;
                            for (idx, hash) in assignments {
                                let path = format!("/rest/block/{}.bin", hash);
                                match conn.get(&path) {
                                    Ok(block) => {
                                        if tx.send((idx, hash, block)).is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        err = Some(e.context(format!(
                                            "REST conn {}: block {}",
                                            conn_id, hash
                                        )));
                                        break;
                                    }
                                }
                            }
                            err
                        })
                    })
                    .collect();

                // Drop our copy so channel closes when all fetchers finish.
                drop(tx);

                // Reorder buffer: blocks arrive out of order, consumer needs
                // them in sequence.
                let mut next_idx = 0;
                let mut pending: std::collections::HashMap<usize, (BlockHash, SerBlock)> =
                    std::collections::HashMap::new();

                for (idx, hash, block) in rx {
                    pending.insert(idx, (hash, block));

                    // Flush all consecutive ready blocks.
                    while let Some((h, b)) = pending.remove(&next_idx) {
                        blocks_duration.observe_duration("process", || func(h, b));
                        next_idx += 1;
                    }
                }

                // Check for fetcher errors.
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
        let started = Instant::now();
        match self.do_get(path) {
            Ok(body) => {
                let elapsed = started.elapsed();
                if elapsed >= Duration::from_secs(2) {
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
                *self = Self::connect(self.addr)?;
                let retry_started = Instant::now();
                let result = self.do_get(path);
                match &result {
                    Ok(body) => info!(
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
        let notify = tx.try_send(());
        let queued = notify.is_ok();
        let frame_sizes: Vec<usize> = frames.iter().map(Vec::len).collect();
        let payload_hex = frames
            .first()
            .map(|frame| bytes_hex(frame))
            .unwrap_or_default();
        info!(
            "[blake2b-diag] ZMQ event topic={} frame_sizes={:?} payload_hex={} notification_queued={}",
            String::from_utf8_lossy(&topic),
            frame_sizes,
            payload_hex,
            queued,
        );
    });

    Ok(rx)
}

fn header_kind(header: &AnyHeader) -> &'static str {
    match header {
        AnyHeader::V1(_) => "v1",
        AnyHeader::V2(_) => "v2",
    }
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
