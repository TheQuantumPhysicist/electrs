use anyhow::{bail, Context, Result};
use bitcoin::{
    consensus::deserialize, hashes::hex::FromHex, hex::DisplayHex, BlockHash, Transaction, Txid,
};
use crossbeam_channel::Receiver;
use rayon::prelude::*;
use serde_derive::Deserialize;
use serde_json::{self, json, Value};

use std::collections::{hash_map::Entry, HashMap};
use std::fmt;
use std::iter::FromIterator;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, OnceLock,
};
use std::time::{Duration, Instant};

use crate::{
    cache::Cache,
    config::{Config, ELECTRS_VERSION},
    daemon::{self, extract_bitcoind_error, Daemon},
    merkle::Proof,
    metrics::{self, Histogram, Metrics},
    signals::Signal,
    status::ScriptHashStatus,
    tracker::Tracker,
    types::ScriptHash,
};

const UNKNOWN_FEE: isize = -1; // (allowed by Electrum protocol)

const UNSUBSCRIBED_QUERY_MESSAGE: &str = "your wallet uses less efficient method of querying electrs, consider contacting the developer of your wallet. Reason:";

struct SubscribeDiagEntry {
    started: Instant,
    phase_started: Instant,
    phase: &'static str,
    requested: usize,
    new_count: usize,
}

static SUBSCRIBE_DIAG_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static SUBSCRIBE_DIAG: OnceLock<Mutex<HashMap<u64, SubscribeDiagEntry>>> = OnceLock::new();

fn subscribe_diag() -> &'static Mutex<HashMap<u64, SubscribeDiagEntry>> {
    SUBSCRIBE_DIAG.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn diagnostic_subscribe_state() -> String {
    let active = subscribe_diag()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let mut entries: Vec<String> = active
        .iter()
        .map(|(id, entry)| {
            format!(
                "id={} total_ms={} phase={} phase_ms={} requested={} new={}",
                id,
                entry.started.elapsed().as_millis(),
                entry.phase,
                entry.phase_started.elapsed().as_millis(),
                entry.requested,
                entry.new_count,
            )
        })
        .collect();
    entries.sort();
    if entries.len() > 8 {
        entries.truncate(8);
        entries.push("more-subscriptions-omitted".to_owned());
    }
    format!("active={} calls=[{}]", active.len(), entries.join("; "))
}

struct SubscribeDiagGuard {
    id: u64,
}

impl SubscribeDiagGuard {
    fn new(requested: usize) -> Self {
        let id = SUBSCRIBE_DIAG_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        subscribe_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(
                id,
                SubscribeDiagEntry {
                    started: now,
                    phase_started: now,
                    phase: "filter-existing",
                    requested,
                    new_count: 0,
                },
            );
        Self { id }
    }

    fn set_phase(&self, phase: &'static str, new_count: usize) {
        let mut active = subscribe_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(entry) = active.get_mut(&self.id) {
            let elapsed = entry.phase_started.elapsed();
            if elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow subscribe phase id={} phase={} elapsed_ms={} requested={} new={}",
                    self.id,
                    entry.phase,
                    elapsed.as_millis(),
                    entry.requested,
                    entry.new_count,
                );
            }
            entry.phase = phase;
            entry.phase_started = Instant::now();
            entry.new_count = new_count;
        }
    }
}

impl Drop for SubscribeDiagGuard {
    fn drop(&mut self) {
        let entry = subscribe_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.id);
        if let Some(entry) = entry {
            let elapsed = entry.started.elapsed();
            if elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow subscribe id={} elapsed_ms={} final_phase={} final_phase_ms={} requested={} new={}",
                    self.id,
                    elapsed.as_millis(),
                    entry.phase,
                    entry.phase_started.elapsed().as_millis(),
                    entry.requested,
                    entry.new_count,
                );
            }
        }
    }
}

/// Per-client Electrum protocol state
#[derive(Default)]
pub struct Client {
    tip: Option<BlockHash>,
    scripthashes: HashMap<ScriptHash, ScriptHashStatus>,
    negotiated: Option<&'static str>,
}

impl Client {
    pub(crate) fn diagnostic_state(&self) -> (bool, usize, Option<&'static str>) {
        (self.tip.is_some(), self.scripthashes.len(), self.negotiated)
    }
}

#[derive(Deserialize)]
struct Request {
    id: Value,
    method: String,

    #[serde(default)]
    params: Value,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Requests {
    Single(Request),
    Batch(Vec<Request>),
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
enum VersionRequest {
    Single(String),
    MinMax(String, String),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TxGetArgs {
    Txid((Txid,)),
    TxidVerbose(Txid, bool),
}

impl From<&TxGetArgs> for (Txid, bool) {
    fn from(args: &TxGetArgs) -> Self {
        match args {
            TxGetArgs::Txid((txid,)) => (*txid, false),
            TxGetArgs::TxidVerbose(txid, verbose) => (*txid, *verbose),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BroadcastArgs {
    Package((Vec<String>,)),
    PackageVerbose((Vec<String>, bool)),
}

impl BroadcastArgs {
    fn txs(&self) -> &[String] {
        match self {
            BroadcastArgs::Package((txs,)) => txs,
            BroadcastArgs::PackageVerbose((txs, _)) => txs,
        }
    }

    fn verbose(&self) -> bool {
        match self {
            BroadcastArgs::Package(_) => false,
            BroadcastArgs::PackageVerbose((_, verbose)) => *verbose,
        }
    }
}

enum StandardError {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
}

enum RpcError {
    // JSON-RPC spec errors
    Standard(StandardError),
    // Electrum-specific errors
    BadRequest(anyhow::Error),
    DaemonError(daemon::RpcError),
    UnavailableIndex,
}

impl RpcError {
    fn to_value(&self) -> Value {
        match self {
            RpcError::Standard(err) => match err {
                StandardError::ParseError => json!({"code": -32700, "message": "parse error"}),
                StandardError::InvalidRequest => {
                    json!({"code": -32600, "message": "invalid request"})
                }
                StandardError::MethodNotFound => {
                    json!({"code": -32601, "message": "method not found"})
                }
                StandardError::InvalidParams => {
                    json!({"code": -32602, "message": "invalid params"})
                }
            },
            RpcError::BadRequest(err) => json!({"code": 1, "message": err.to_string()}),
            RpcError::DaemonError(err) => json!({"code": 2, "message": err.message}),
            RpcError::UnavailableIndex => {
                // Internal JSON-RPC error (https://www.jsonrpc.org/specification#error_object)
                json!({"code": -32603, "message": "unavailable index"})
            }
        }
    }
}

/// Electrum RPC handler
pub struct Rpc {
    tracker: Tracker,
    cache: Cache,
    rpc_duration: Histogram,
    daemon: Daemon,
    signal: Signal,
    banner: String,
    port: u16,
}

impl Rpc {
    /// Perform initial index sync (may take a while on first run).
    pub fn new(config: &Config, metrics: Metrics) -> Result<Self> {
        let rpc_duration = metrics.histogram_vec(
            "rpc_duration",
            "RPC duration (in seconds)",
            "method",
            metrics::default_duration_buckets(),
        );

        let tracker = Tracker::new(config, metrics)?;
        let signal = Signal::new();
        let daemon = Daemon::connect(config, signal.exit_flag(), tracker.metrics())?;
        let cache = Cache::new(tracker.metrics());
        Ok(Self {
            tracker,
            cache,
            rpc_duration,
            daemon,
            signal,
            banner: config.server_banner.clone(),
            port: config.electrum_rpc_addr.port(),
        })
    }

    pub(crate) fn signal(&self) -> &Signal {
        &self.signal
    }

    pub fn new_block_notification(&self) -> Receiver<()> {
        self.daemon.new_block_notification()
    }

    pub fn sync(&mut self) -> Result<bool> {
        self.tracker.sync(&self.daemon, self.signal.exit_flag())
    }

    pub fn update_client(&self, client: &mut Client) -> Result<Vec<String>> {
        let chain = self.tracker.chain();
        let mut notifications = client
            .scripthashes
            .par_iter_mut()
            .filter_map(|(scripthash, status)| -> Option<Result<Value>> {
                match self
                    .tracker
                    .update_scripthash_status(status, &self.daemon, &self.cache)
                {
                    Ok(true) => Some(Ok(notification(
                        "blockchain.scripthash.subscribe",
                        &[json!(scripthash), json!(status.statushash())],
                    ))),
                    Ok(false) => None, // statushash is the same
                    Err(e) => Some(Err(e)),
                }
            })
            .collect::<Result<Vec<Value>>>()
            .context("failed to update status")?;

        if let Some(old_tip) = client.tip {
            let new_tip = self.tracker.chain().tip();
            if old_tip != new_tip {
                self.check_may_serve_headers(client)?;
                client.tip = Some(new_tip);
                let height = chain.height();
                let header = chain.get_block_header(height).unwrap();
                notifications.push(notification(
                    "blockchain.headers.subscribe",
                    &[json!({"hex": header.serialize_hex(), "height": height})],
                ));
            }
        }
        Ok(notifications.into_iter().map(|v| v.to_string()).collect())
    }

    fn headers_subscribe(&self, client: &mut Client) -> Result<Value> {
        self.check_may_serve_headers(client)?;
        let chain = self.tracker.chain();
        client.tip = Some(chain.tip());
        let height = chain.height();
        let header = chain.get_block_header(height).unwrap();
        Ok(json!({"hex": header.serialize_hex(), "height": height}))
    }

    fn block_header(&self, client: &Client, (height,): (usize,)) -> Result<Value> {
        self.check_may_serve_headers(client)?;
        let chain = self.tracker.chain();
        let header = match chain.get_block_header(height) {
            None => bail!("no header at {}", height),
            Some(header) => header,
        };
        Ok(json!(header.serialize_hex()))
    }

    fn block_headers(
        &self,
        client: &Client,
        (start_height, count): (usize, usize),
    ) -> Result<Value> {
        self.check_may_serve_headers(client)?;
        let chain = self.tracker.chain();
        let max_count = 2016usize;
        // return only the available block headers
        let end_height = std::cmp::min(
            chain.height() + 1,
            start_height + std::cmp::min(count, max_count),
        );
        let heights = start_height..end_height;
        let count = heights.len();
        let hex_headers =
            heights.filter_map(|height| chain.get_block_header(height).map(|h| h.serialize_hex()));

        Ok(json!({"count": count, "hex": String::from_iter(hex_headers), "max": max_count}))
    }

    fn estimate_fee(&self, (nblocks,): (u16,)) -> Result<Value> {
        Ok(self
            .daemon
            .estimate_fee(nblocks)?
            .map(|fee_rate| json!(fee_rate.to_btc()))
            .unwrap_or_else(|| json!(UNKNOWN_FEE)))
    }

    fn relayfee(&self) -> Result<Value> {
        Ok(json!(self.daemon.get_relay_fee()?.to_btc())) // [BTC/kB]
    }

    fn scripthash_get_balance(
        &self,
        client: &Client,
        (scripthash,): &(ScriptHash,),
    ) -> Result<Value> {
        let balance = match client.scripthashes.get(scripthash) {
            Some(status) => self.tracker.get_balance(status),
            None => {
                info!(
                    "{} blockchain.scripthash.get_balance called for unsubscribed scripthash",
                    UNSUBSCRIBED_QUERY_MESSAGE
                );
                self.tracker.get_balance(&self.new_status(*scripthash)?)
            }
        };
        Ok(json!(balance))
    }

    fn scripthash_get_history(
        &self,
        client: &Client,
        (scripthash,): &(ScriptHash,),
    ) -> Result<Value> {
        let history_entries = match client.scripthashes.get(scripthash) {
            Some(status) => json!(status.get_history()),
            None => {
                info!(
                    "{} blockchain.scripthash.get_history called for unsubscribed scripthash",
                    UNSUBSCRIBED_QUERY_MESSAGE
                );
                json!(self.new_status(*scripthash)?.get_history())
            }
        };
        Ok(history_entries)
    }

    fn scripthash_list_unspent(
        &self,
        client: &Client,
        (scripthash,): &(ScriptHash,),
    ) -> Result<Value> {
        let unspent_entries = match client.scripthashes.get(scripthash) {
            Some(status) => self.tracker.get_unspent(status),
            None => {
                info!(
                    "{} blockchain.scripthash.listunspent called for unsubscribed scripthash",
                    UNSUBSCRIBED_QUERY_MESSAGE
                );
                self.tracker.get_unspent(&self.new_status(*scripthash)?)
            }
        };
        Ok(json!(unspent_entries))
    }

    fn scripthash_subscribe(
        &self,
        client: &mut Client,
        (scripthash,): &(ScriptHash,),
    ) -> Result<Value> {
        self.scripthashes_subscribe(client, &[*scripthash])
            .next()
            .unwrap()
    }

    fn scripthash_unsubscribe(
        &self,
        client: &mut Client,
        (scripthash,): &(ScriptHash,),
    ) -> Result<Value> {
        let removed = client.scripthashes.remove(scripthash).is_some();
        Ok(json!(removed))
    }

    fn scripthashes_subscribe<'a>(
        &self,
        client: &'a mut Client,
        scripthashes: &'a [ScriptHash],
    ) -> impl Iterator<Item = Result<Value>> + 'a {
        let diag = SubscribeDiagGuard::new(scripthashes.len());
        for (subscription_index, scripthash) in scripthashes.iter().enumerate() {
            warn!(
                "THISISPRIVATE [blake2b-diag] wallet subscription subscribe_id={} subscription_index={} requested={} already_subscribed={} scripthash={}",
                diag.id,
                subscription_index,
                scripthashes.len(),
                client.scripthashes.contains_key(scripthash),
                scripthash,
            );
        }
        let new_scripthashes: Vec<ScriptHash> = scripthashes
            .iter()
            .copied()
            .filter(|scripthash| !client.scripthashes.contains_key(scripthash))
            .collect();

        diag.set_phase("rayon-new-status", new_scripthashes.len());
        let mut results: HashMap<ScriptHash, Result<ScriptHashStatus>> = new_scripthashes
            .into_par_iter()
            .map(|scripthash| (scripthash, self.new_status(scripthash)))
            .collect();
        diag.set_phase("build-results", results.len());

        scripthashes.iter().map(move |scripthash| {
            let statushash = match client.scripthashes.entry(*scripthash) {
                Entry::Occupied(e) => e.get().statushash(),
                Entry::Vacant(e) => {
                    let status = results
                        .remove(scripthash)
                        .expect("missing scripthash status")?; // return an error for failed subscriptions
                    e.insert(status).statushash()
                }
            };
            Ok(json!(statushash))
        })
    }

    fn new_status(&self, scripthash: ScriptHash) -> Result<ScriptHashStatus> {
        let mut status = ScriptHashStatus::new(scripthash);
        self.tracker
            .update_scripthash_status(&mut status, &self.daemon, &self.cache)?;
        Ok(status)
    }

    fn transaction_broadcast(&self, (tx_hex,): &(String,)) -> Result<Value> {
        let txid = self.daemon.broadcast(&tx_from_hex(tx_hex)?)?;
        Ok(json!(txid))
    }

    fn transaction_broadcast_package(&self, args: &BroadcastArgs) -> Result<Value> {
        let txs: Vec<Transaction> = args
            .txs()
            .iter()
            .map(|s| tx_from_hex(s))
            .collect::<Result<_>>()?;
        let response = self.daemon.submitpackage(&txs)?;
        if args.verbose() {
            return Ok(response);
        }
        let build_result = || -> Option<Value> {
            let success = response.get("package_msg")? == &json!("success");

            let mut errors = vec![];
            for tx in response.get("tx-results")?.as_object()?.values() {
                let tx_obj = tx.as_object()?;
                if let Some(error) = tx_obj.get("error") {
                    let txid = tx_obj.get("txid");
                    errors.push(json!({"error": error, "txid": txid}));
                }
            }
            Some(if errors.is_empty() {
                json!({"success": success})
            } else {
                json!({"success": success, "errors": errors})
            })
        };
        build_result().ok_or(anyhow!("Unexpected `submitpackage` response"))
    }

    fn transaction_get(&self, args: &TxGetArgs) -> Result<Value> {
        let (txid, verbose) = args.into();
        if verbose {
            let blockhash = self
                .tracker
                .lookup_transaction(&self.daemon, txid)?
                .map(|(blockhash, _tx)| blockhash);
            return self.daemon.get_transaction_info(&txid, blockhash);
        }
        // if the scripthash was subscribed, tx should be cached
        if let Some(tx_hex) = self
            .cache
            .get_tx(&txid, |tx_bytes| tx_bytes.to_lower_hex_string())
        {
            return Ok(json!(tx_hex));
        }
        debug!("tx cache miss: txid={}", txid);
        // use internal index to load confirmed transaction
        if let Some(tx_hex) = self
            .tracker
            .lookup_transaction(&self.daemon, txid)?
            .map(|(_blockhash, tx)| tx.to_lower_hex_string())
        {
            return Ok(json!(tx_hex));
        }
        // load unconfirmed transaction via RPC
        Ok(json!(self.daemon.get_transaction_hex(&txid, None)?))
    }

    fn transaction_get_merkle(&self, (txid, height): &(Txid, usize)) -> Result<Value> {
        let chain = self.tracker.chain();
        let blockhash = match chain.get_block_hash(*height) {
            None => bail!("missing block at {}", height),
            Some(blockhash) => blockhash,
        };
        let txids = self.daemon.get_block_txids(blockhash)?;
        match txids.iter().position(|current_txid| *current_txid == *txid) {
            None => bail!("missing txid {} in block {}", txid, blockhash),
            Some(position) => {
                let proof = Proof::create(&txids, position);
                Ok(json!({
                    "block_height": height,
                    "pos": proof.position(),
                    "merkle": proof.to_hex(),
                }))
            }
        }
    }

    fn transaction_from_pos(
        &self,
        (height, tx_pos, merkle): (usize, usize, bool),
    ) -> Result<Value> {
        let chain = self.tracker.chain();
        let blockhash = match chain.get_block_hash(height) {
            None => bail!("missing block at {}", height),
            Some(blockhash) => blockhash,
        };
        let txids = self.daemon.get_block_txids(blockhash)?;
        if tx_pos >= txids.len() {
            bail!("invalid tx_pos {} in block at height {}", tx_pos, height);
        }
        let txid: Txid = txids[tx_pos];
        if merkle {
            let proof = Proof::create(&txids, tx_pos);
            Ok(json!({"tx_hash": txid, "merkle": proof.to_hex()}))
        } else {
            Ok(json!({ "tx_hash": txid }))
        }
    }

    fn get_fee_histogram(&self) -> Result<Value> {
        Ok(json!(self.tracker.fees_histogram()))
    }

    fn server_id(&self) -> String {
        format!("electrs/{}", ELECTRS_VERSION)
    }

    fn protocol_version(&self) -> &'static str {
        crate::headerv2::protocol_version(self.tracker.chain().has_v2_headers())
    }

    fn check_may_serve_headers(&self, client: &Client) -> Result<()> {
        let chain_has_v2 = self.tracker.chain().has_v2_headers();
        if crate::headerv2::may_serve_headers(chain_has_v2, client.negotiated) {
            Ok(())
        } else {
            bail!(
                "refusing block headers to a client at protocol {}: {}",
                client.negotiated.unwrap_or("(unnegotiated)"),
                crate::headerv2::HEADER_REFUSAL
            )
        }
    }

    fn version(
        &self,
        client: &mut Client,
        (client_id, client_version): &(String, VersionRequest),
    ) -> Result<Value> {
        let version = self.protocol_version();
        match client_version {
            VersionRequest::Single(exact) => check_between(version, exact, exact),
            VersionRequest::MinMax(min, max) => check_between(version, min, max),
        }
        .with_context(|| {
            if version == crate::headerv2::PROTOCOL_VERSION_V2 {
                format!(
                    "unsupported request {:?} by {}: this chain uses 164-byte block headers with a BLAKE2b block hash, which a client below protocol {} cannot read",
                    client_version, client_id, version
                )
            } else {
                format!("unsupported request {:?} by {}", client_version, client_id)
            }
        })?;
        client.negotiated = Some(version);
        Ok(json!([self.server_id(), version]))
    }

    fn features(&self) -> Result<Value> {
        let chain = self.tracker.chain();
        let version = self.protocol_version();
        let mut features = json!({
            "genesis_hash": chain.get_block_hash(0),
            "hosts": { "tcp_port": self.port },
            "protocol_max": version,
            "protocol_min": version,
            "pruning": null,
            "server_version": self.server_id(),
            "hash_function": "sha256"
        });
        if let Some(fork) = crate::headerv2::fork_point(chain) {
            features["blake2b_fork"] = fork;
        }
        Ok(features)
    }

    pub fn handle_requests(&self, client: &mut Client, lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                if line.contains("\"blockchain.scripthash.subscribe\"") {
                    warn!(
                        "THISISPRIVATE [blake2b-diag] raw Electrum subscribe request line={}",
                        line
                    );
                }
                parse_requests(line)
                    .map(Calls::parse)
                    .map_err(error_msg_no_id)
            })
            .map(|calls| self.handle_calls(client, calls).to_string())
            .collect()
    }

    fn handle_calls(&self, client: &mut Client, calls: Result<Calls, Value>) -> Value {
        let calls: Calls = match calls {
            Ok(calls) => calls,
            Err(response) => return response, // JSON parsing failed - the response does not contain request id
        };

        match calls {
            Calls::Batch(batch) => {
                if let Some(result) = self.try_multi_call(client, &batch) {
                    return json!(result);
                }
                json!(batch
                    .into_iter()
                    .map(|result| self.single_call(client, result))
                    .collect::<Vec<Value>>())
            }
            Calls::Single(result) => self.single_call(client, result),
        }
    }

    fn try_multi_call(
        &self,
        client: &mut Client,
        calls: &[Result<Call, Value>],
    ) -> Option<Vec<Value>> {
        // exit if any call failed to parse
        let valid_calls = calls
            .iter()
            .map(|result| result.as_ref().ok())
            .collect::<Option<Vec<&Call>>>()?;

        // only "blockchain.scripthashes.subscribe" are supported
        let scripthashes: Vec<ScriptHash> = valid_calls
            .iter()
            .map(|call| match &call.params {
                Params::ScriptHashSubscribe((scripthash,)) => Some(*scripthash),
                _ => None, // exit if any of the calls is not supported
            })
            .collect::<Option<Vec<ScriptHash>>>()?;

        Some(
            self.rpc_duration
                .observe_duration("blockchain.scripthash.subscribe:multi", || {
                    self.scripthashes_subscribe(client, &scripthashes)
                        .zip(valid_calls)
                        .map(|(result, call)| call.response(result))
                        .collect::<Vec<Value>>()
                }),
        )
    }

    fn single_call(&self, client: &mut Client, call: Result<Call, Value>) -> Value {
        let call = match call {
            Ok(call) => call,
            Err(response) => return response, // params parsing may fail - the response contains request id
        };
        self.rpc_duration.observe_duration(&call.method, || {
            if self.tracker.status().is_err() {
                // Allow only a few RPC (for sync status notification) not requiring index DB being compacted.
                match &call.params {
                    Params::BlockHeader(_)
                    | Params::BlockHeaders(_)
                    | Params::HeadersSubscribe
                    | Params::Version(_) => (),
                    _ => return error_msg(&call.id, RpcError::UnavailableIndex),
                };
            }
            let result = match &call.params {
                Params::Banner => Ok(json!(self.banner)),
                Params::BlockHeader(args) => self.block_header(client, *args),
                Params::BlockHeaders(args) => self.block_headers(client, *args),
                Params::Donation => Ok(Value::Null),
                Params::EstimateFee(args) => self.estimate_fee(*args),
                Params::Features => self.features(),
                Params::HeadersSubscribe => self.headers_subscribe(client),
                Params::MempoolFeeHistogram => self.get_fee_histogram(),
                Params::PeersSubscribe => Ok(json!([])),
                Params::Ping => Ok(Value::Null),
                Params::RelayFee => self.relayfee(),
                Params::ScriptHashGetBalance(args) => self.scripthash_get_balance(client, args),
                Params::ScriptHashGetHistory(args) => self.scripthash_get_history(client, args),
                Params::ScriptHashListUnspent(args) => self.scripthash_list_unspent(client, args),
                Params::ScriptHashSubscribe(args) => self.scripthash_subscribe(client, args),
                Params::ScriptHashUnsubscribe(args) => self.scripthash_unsubscribe(client, args),
                Params::TransactionBroadcast(args) => self.transaction_broadcast(args),
                Params::TransactionBroadcastPackage(args) => {
                    self.transaction_broadcast_package(args)
                }
                Params::TransactionGet(args) => self.transaction_get(args),
                Params::TransactionGetMerkle(args) => self.transaction_get_merkle(args),
                Params::TransactionFromPosition(args) => self.transaction_from_pos(*args),
                Params::Version(args) => self.version(client, args),
            };
            call.response(result)
        })
    }
}

#[derive(Deserialize)]
enum Params {
    Banner,
    BlockHeader((usize,)),
    BlockHeaders((usize, usize)),
    TransactionBroadcast((String,)),
    TransactionBroadcastPackage(BroadcastArgs),
    Donation,
    EstimateFee((u16,)),
    Features,
    HeadersSubscribe,
    MempoolFeeHistogram,
    PeersSubscribe,
    Ping,
    RelayFee,
    ScriptHashGetBalance((ScriptHash,)),
    ScriptHashGetHistory((ScriptHash,)),
    ScriptHashListUnspent((ScriptHash,)),
    ScriptHashSubscribe((ScriptHash,)),
    ScriptHashUnsubscribe((ScriptHash,)),
    TransactionGet(TxGetArgs),
    TransactionGetMerkle((Txid, usize)),
    TransactionFromPosition((usize, usize, bool)),
    Version((String, VersionRequest)),
}

impl Params {
    fn parse(method: &str, params: Value) -> std::result::Result<Params, StandardError> {
        Ok(match method {
            "blockchain.block.header" => Params::BlockHeader(convert(params)?),
            "blockchain.block.headers" => Params::BlockHeaders(convert(params)?),
            "blockchain.estimatefee" => Params::EstimateFee(convert(params)?),
            "blockchain.headers.subscribe" => Params::HeadersSubscribe,
            "blockchain.relayfee" => Params::RelayFee,
            "blockchain.scripthash.get_balance" => Params::ScriptHashGetBalance(convert(params)?),
            "blockchain.scripthash.get_history" => Params::ScriptHashGetHistory(convert(params)?),
            "blockchain.scripthash.listunspent" => Params::ScriptHashListUnspent(convert(params)?),
            "blockchain.scripthash.subscribe" => Params::ScriptHashSubscribe(convert(params)?),
            "blockchain.scripthash.unsubscribe" => Params::ScriptHashUnsubscribe(convert(params)?),
            "blockchain.transaction.broadcast" => Params::TransactionBroadcast(convert(params)?),
            "blockchain.transaction.broadcast_package" => {
                Params::TransactionBroadcastPackage(convert(params)?)
            }
            "blockchain.transaction.get" => Params::TransactionGet(convert(params)?),
            "blockchain.transaction.get_merkle" => Params::TransactionGetMerkle(convert(params)?),
            "blockchain.transaction.id_from_pos" => {
                Params::TransactionFromPosition(convert(params)?)
            }
            "mempool.get_fee_histogram" => Params::MempoolFeeHistogram,
            "server.banner" => Params::Banner,
            "server.donation_address" => Params::Donation,
            "server.features" => Params::Features,
            "server.peers.subscribe" => Params::PeersSubscribe,
            "server.ping" => Params::Ping,
            "server.version" => Params::Version(convert(params)?),
            _ => {
                warn!("unknown method {}", method);
                return Err(StandardError::MethodNotFound);
            }
        })
    }
}

struct Call {
    id: Value,
    method: String,
    params: Params,
}

impl Call {
    fn parse(request: Request) -> Result<Call, Value> {
        match Params::parse(&request.method, request.params) {
            Ok(params) => Ok(Call {
                id: request.id,
                method: request.method,
                params,
            }),
            Err(e) => Err(error_msg(&request.id, RpcError::Standard(e))),
        }
    }

    fn response(&self, result: Result<Value>) -> Value {
        match result {
            Ok(value) => result_msg(&self.id, value),
            Err(err) => {
                warn!("RPC {} failed: {:#}", self.method, err);
                match err
                    .downcast_ref::<bitcoincore_rpc::Error>()
                    .and_then(extract_bitcoind_error)
                {
                    Some(e) => error_msg(&self.id, RpcError::DaemonError(e.clone())),
                    None => error_msg(&self.id, RpcError::BadRequest(err)),
                }
            }
        }
    }
}

enum Calls {
    Batch(Vec<Result<Call, Value>>),
    Single(Result<Call, Value>),
}

impl Calls {
    fn parse(requests: Requests) -> Calls {
        match requests {
            Requests::Single(request) => Calls::Single(Call::parse(request)),
            Requests::Batch(batch) => {
                Calls::Batch(batch.into_iter().map(Call::parse).collect::<Vec<_>>())
            }
        }
    }
}

fn convert<T>(params: Value) -> std::result::Result<T, StandardError>
where
    T: serde::de::DeserializeOwned,
{
    let params_str = params.to_string();
    serde_json::from_value(params).map_err(|err| {
        warn!("invalid params {}: {}", params_str, err);
        StandardError::InvalidParams
    })
}

fn notification(method: &str, params: &[Value]) -> Value {
    json!({"jsonrpc": "2.0", "method": method, "params": params})
}

fn result_msg(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_msg(id: &Value, error: RpcError) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": error.to_value()})
}

fn error_msg_no_id(err: StandardError) -> Value {
    error_msg(&Value::Null, RpcError::Standard(err))
}

fn parse_requests(line: &str) -> Result<Requests, StandardError> {
    match serde_json::from_str(line) {
        // parse JSON from str
        Ok(value) => match serde_json::from_value(value) {
            // parse RPC from JSON
            Ok(requests) => Ok(requests),
            Err(err) => {
                warn!("invalid RPC request ({:?}): {}", line, err);
                Err(StandardError::InvalidRequest)
            }
        },
        Err(err) => {
            warn!("invalid JSON ({:?}): {}", line, err);
            Err(StandardError::ParseError)
        }
    }
}

fn parse_version(version: &str) -> Result<Version> {
    let result = version
        .split('.')
        .map(|part| usize::from_str(part).with_context(|| format!("invalid version {}", version)))
        .collect::<Result<Vec<usize>>>()?;
    Ok(Version(result))
}

#[derive(PartialOrd, PartialEq, Debug)]
struct Version(Vec<usize>);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, v) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", v)?;
        }
        Ok(())
    }
}

fn check_between(version_str: &str, min_str: &str, max_str: &str) -> Result<()> {
    let version = parse_version(version_str)?;
    let min = parse_version(min_str)?;
    if version < min {
        bail!("version {} < {}", version, min);
    }
    let max = parse_version(max_str)?;
    if version > max {
        bail!("version {} > {}", version, max);
    }
    Ok(())
}

fn tx_from_hex(tx_hex: &str) -> Result<Transaction> {
    let tx_bytes = Vec::from_hex(tx_hex).context("non-hex transaction")?;
    let tx = deserialize(&tx_bytes).context("invalid transaction")?;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(parse_version("1").unwrap(), Version(vec![1]));
        assert_eq!(parse_version("1.2").unwrap(), Version(vec![1, 2]));
        assert_eq!(parse_version("1.2.345").unwrap(), Version(vec![1, 2, 345]));

        assert!(parse_version("1.2").unwrap() < parse_version("1.100").unwrap());
    }

    #[test]
    fn test_between() {
        assert!(check_between("1.4", "1.4", "1.4").is_ok());
        assert!(check_between("1.4", "1.4", "1.5").is_ok());
        assert!(check_between("1.4", "1.3", "1.4").is_ok());
        assert!(check_between("1.4", "1.3", "1.5").is_ok());

        assert!(check_between("1.4", "1.5", "1.5").is_err());
        assert!(check_between("1.4", "1.3", "1.3").is_err());
        assert!(check_between("1.4", "1.4.1", "1.5").is_err());
        assert!(check_between("1.4", "1", "1").is_err());
    }

    #[test]
    fn test_requests() {
        assert!(matches!(
            parse_requests("foo"),
            Err(StandardError::ParseError)
        ));
        assert!(matches!(
            parse_requests(r"{}"),
            Err(StandardError::InvalidRequest)
        ));
        assert!(parse_requests(r#"{"id":1,"method":"name","params":[]}"#).is_ok());
        assert!(parse_requests(r#"{"id":1,"method":"name","params":[],"unrelated":42}"#).is_ok());
        assert!(parse_requests(r#" { "id" : 1 , "method" : "name" , "params" : [ ] } "#).is_ok());
    }
}
