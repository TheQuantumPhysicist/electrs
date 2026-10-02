use anyhow::Result;
use bitcoin::{
    consensus::serialize,
    hashes::{sha256, Hash, HashEngine},
    Amount, BlockHash, OutPoint, SignedAmount, Transaction, Txid,
};
use bitcoin_slices::{bsl, Visitor};
use rayon::prelude::*;
use serde::ser::{Serialize, Serializer};

use crate::headerv2::{visit_block_txs, AnyHeader};

use std::convert::TryFrom;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::ControlFlow,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use crate::{
    cache::Cache,
    chain::Chain,
    daemon::Daemon,
    index::Index,
    mempool::Mempool,
    types::{bsl_txid, ScriptHash, SerBlock, StatusHash, HASH_PREFIX_LEN},
};

struct StatusSyncDiagEntry {
    started: Instant,
    phase_started: Instant,
    phase: &'static str,
    detail: String,
}

static STATUS_SYNC_DIAG_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static STATUS_SYNC_DIAG: OnceLock<Mutex<HashMap<u64, StatusSyncDiagEntry>>> = OnceLock::new();

fn status_sync_diag() -> &'static Mutex<HashMap<u64, StatusSyncDiagEntry>> {
    STATUS_SYNC_DIAG.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn diagnostic_status_state() -> String {
    let active = status_sync_diag()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let mut entries: Vec<String> = active
        .iter()
        .map(|(id, entry)| {
            format!(
                "id={} total_ms={} phase={} phase_ms={} detail=[{}]",
                id,
                entry.started.elapsed().as_millis(),
                entry.phase,
                entry.phase_started.elapsed().as_millis(),
                entry.detail,
            )
        })
        .collect();
    entries.sort();
    if entries.len() > 8 {
        entries.truncate(8);
        entries.push("more-status-syncs-omitted".to_owned());
    }
    format!("active={} syncs=[{}]", active.len(), entries.join("; "))
}

struct StatusSyncDiagGuard {
    id: u64,
}

impl StatusSyncDiagGuard {
    fn new() -> Self {
        let id = STATUS_SYNC_DIAG_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        status_sync_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(
                id,
                StatusSyncDiagEntry {
                    started: now,
                    phase_started: now,
                    phase: "start",
                    detail: String::new(),
                },
            );
        Self { id }
    }

    fn set_phase(&self, phase: &'static str, detail: String) {
        let mut active = status_sync_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(entry) = active.get_mut(&self.id) {
            let phase_elapsed = entry.phase_started.elapsed();
            if phase_elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow status phase id={} phase={} elapsed_ms={} detail=[{}]",
                    self.id,
                    entry.phase,
                    phase_elapsed.as_millis(),
                    entry.detail,
                );
            }
            entry.phase = phase;
            entry.phase_started = Instant::now();
            entry.detail = detail;
        }
    }
}

impl Drop for StatusSyncDiagGuard {
    fn drop(&mut self) {
        let entry = status_sync_diag()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.id);
        if let Some(entry) = entry {
            let elapsed = entry.started.elapsed();
            if elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow status sync id={} elapsed_ms={} final_phase={} final_phase_ms={} detail=[{}]",
                    self.id,
                    elapsed.as_millis(),
                    entry.phase,
                    entry.phase_started.elapsed().as_millis(),
                    entry.detail,
                );
            }
        }
    }
}

const FILTER_AUDIT_MIN_CANDIDATES: usize = 1_000;
const FILTER_NODE_CROSSCHECK_MIN_CANDIDATES: usize = 50_000;
const FILTER_NODE_CROSSCHECK_V1_SAMPLES: usize = 1;
const FILTER_NODE_CROSSCHECK_V2_SAMPLES: usize = 3;

#[derive(Default)]
struct CandidateAudit {
    entries: usize,
    unique_blocks: usize,
    min_height: Option<usize>,
    max_height: Option<usize>,
    v1_entries: usize,
    v2_entries: usize,
    unknown_entries: usize,
    v1_unique_blocks: usize,
    v2_unique_blocks: usize,
    unknown_unique_blocks: usize,
}

fn classify_candidate(index: &Index, blockhash: &BlockHash) -> (Option<usize>, Option<bool>) {
    let Some(height) = index.chain().get_block_height(blockhash) else {
        return (None, None);
    };
    let is_v2 = index
        .chain()
        .get_block_header(height)
        .map(AnyHeader::is_v2);
    (Some(height), is_v2)
}

fn candidate_audit<'a>(
    index: &Index,
    blockhashes: impl IntoIterator<Item = &'a BlockHash>,
) -> CandidateAudit {
    let mut audit = CandidateAudit::default();
    let mut unique = HashSet::<BlockHash>::new();

    for blockhash in blockhashes {
        audit.entries += 1;
        let (height, is_v2) = classify_candidate(index, blockhash);
        if let Some(height) = height {
            audit.min_height = Some(audit.min_height.map_or(height, |current| current.min(height)));
            audit.max_height = Some(audit.max_height.map_or(height, |current| current.max(height)));
        }
        match is_v2 {
            Some(true) => audit.v2_entries += 1,
            Some(false) => audit.v1_entries += 1,
            None => audit.unknown_entries += 1,
        }
        unique.insert(*blockhash);
    }

    audit.unique_blocks = unique.len();
    for blockhash in unique {
        match classify_candidate(index, &blockhash).1 {
            Some(true) => audit.v2_unique_blocks += 1,
            Some(false) => audit.v1_unique_blocks += 1,
            None => audit.unknown_unique_blocks += 1,
        }
    }
    audit
}

fn log_candidate_audit(status_id: u64, kind: &str, audit: &CandidateAudit) {
    if audit.entries < FILTER_AUDIT_MIN_CANDIDATES {
        return;
    }
    warn!(
        "[blake2b-diag] filter audit status_id={} kind={} prefix_bytes={} candidate_entries={} unique_blocks={} duplicate_entries={} height_min={:?} height_max={:?} v1_entries={} v2_entries={} unknown_entries={} v1_unique_blocks={} v2_unique_blocks={} unknown_unique_blocks={}",
        status_id,
        kind,
        HASH_PREFIX_LEN,
        audit.entries,
        audit.unique_blocks,
        audit.entries.saturating_sub(audit.unique_blocks),
        audit.min_height,
        audit.max_height,
        audit.v1_entries,
        audit.v2_entries,
        audit.unknown_entries,
        audit.v1_unique_blocks,
        audit.v2_unique_blocks,
        audit.unknown_unique_blocks,
    );
}

fn filter_audit_report_every(total: usize) -> usize {
    std::cmp::max(10_000, total / 10).max(1)
}

fn audit_sample_candidates(
    index: &Index,
    blockhashes: &[BlockHash],
    confirmed: &HashMap<BlockHash, Vec<TxEntry>>,
) -> Vec<BlockHash> {
    let mut samples = Vec::new();
    let mut v1 = 0usize;
    let mut v2 = 0usize;

    for blockhash in blockhashes {
        if confirmed.contains_key(blockhash) {
            continue;
        }
        match classify_candidate(index, blockhash).1 {
            Some(false) if v1 < FILTER_NODE_CROSSCHECK_V1_SAMPLES => {
                samples.push(*blockhash);
                v1 += 1;
            }
            Some(true) if v2 < FILTER_NODE_CROSSCHECK_V2_SAMPLES => {
                samples.push(*blockhash);
                v2 += 1;
            }
            _ => {}
        }
        if v1 >= FILTER_NODE_CROSSCHECK_V1_SAMPLES
            && v2 >= FILTER_NODE_CROSSCHECK_V2_SAMPLES
        {
            break;
        }
    }
    samples
}

fn matching_output_ordinals(filtered: &[FilteredTx<TxOutput>]) -> Vec<(usize, usize)> {
    let mut ordinals = Vec::new();
    for tx in filtered {
        for output in &tx.result {
            ordinals.push((tx.pos, output.index as usize));
        }
    }
    ordinals.sort_unstable();
    ordinals
}

fn compact_ordinals(ordinals: &[(usize, usize)]) -> String {
    const MAX_LOGGED: usize = 8;
    let mut shown = ordinals
        .iter()
        .take(MAX_LOGGED)
        .map(|(tx, vout)| format!("{}:{}", tx, vout))
        .collect::<Vec<_>>()
        .join(",");
    if ordinals.len() > MAX_LOGGED {
        shown.push_str(&format!(",+{}more", ordinals.len() - MAX_LOGGED));
    }
    shown
}

/// Given a scripthash, store relevant inputs and outputs of a specific transaction
struct TxEntry {
    txid: Txid,
    outputs: Vec<TxOutput>, // relevant funded outputs and their amounts
    spent: Vec<OutPoint>,   // relevant spent outpoints
}

// Funded outputs of a transaction
struct TxOutput {
    index: u32,
    value: Amount,
}

impl TxEntry {
    fn new(txid: Txid) -> Self {
        Self {
            txid,
            outputs: Vec::new(),
            spent: Vec::new(),
        }
    }

    /// Relevant (scripthash-wise) funded outpoints
    fn funding_outpoints(&self) -> impl Iterator<Item = OutPoint> + '_ {
        make_outpoints(self.txid, &self.outputs)
    }
}

// Confirmation height of a transaction or its mempool state:
// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-history
// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-mempool
enum Height {
    Confirmed { height: usize },
    Unconfirmed { has_unconfirmed_inputs: bool },
}

impl Height {
    fn as_i64(&self) -> i64 {
        match self {
            Self::Confirmed { height } => i64::try_from(*height).unwrap(),
            Self::Unconfirmed {
                has_unconfirmed_inputs: true,
            } => -1,
            Self::Unconfirmed {
                has_unconfirmed_inputs: false,
            } => 0,
        }
    }
}

impl Serialize for Height {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.as_i64())
    }
}

impl std::fmt::Display for Height {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_i64().fmt(f)
    }
}

// A single history entry:
// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-history
// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-mempool
#[derive(Serialize)]
pub(crate) struct HistoryEntry {
    #[serde(rename = "tx_hash")]
    txid: Txid,
    height: Height,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "bitcoin::amount::serde::as_sat::opt"
    )]
    fee: Option<Amount>,
}

impl HistoryEntry {
    // Hash to compute ScriptHash status, as defined here:
    // https://electrum-protocol.readthedocs.io/en/latest/protocol-basics.html#status
    fn hash(&self, engine: &mut sha256::HashEngine) {
        let s = format!("{}:{}:", self.txid, self.height);
        engine.input(s.as_bytes());
    }

    fn confirmed(txid: Txid, height: usize) -> Self {
        Self {
            txid,
            height: Height::Confirmed { height },
            fee: None,
        }
    }

    fn unconfirmed(txid: Txid, has_unconfirmed_inputs: bool, fee: Amount) -> Self {
        Self {
            txid,
            height: Height::Unconfirmed {
                has_unconfirmed_inputs,
            },
            fee: Some(fee),
        }
    }
}

/// ScriptHash subscription status
pub struct ScriptHashStatus {
    scripthash: ScriptHash, // specific scripthash to be queried
    tip: BlockHash,         // used for skipping confirmed entries' sync
    confirmed: HashMap<BlockHash, Vec<TxEntry>>, // confirmed entries, partitioned per block (may contain stale blocks)
    mempool: Vec<TxEntry>,                       // unconfirmed entries
    history: Vec<HistoryEntry>,                  // computed from confirmed and mempool entries
    statushash: Option<StatusHash>,              // computed from history
}

/// Specific scripthash balance
/// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-balance
#[derive(Default, Eq, PartialEq, Serialize)]
pub(crate) struct Balance {
    #[serde(with = "bitcoin::amount::serde::as_sat", rename = "confirmed")]
    confirmed_balance: Amount,
    #[serde(with = "bitcoin::amount::serde::as_sat", rename = "unconfirmed")]
    mempool_delta: SignedAmount,
}

/// A single unspent transaction output entry
/// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-listunspent
#[derive(Serialize)]
pub(crate) struct UnspentEntry {
    height: usize, // 0 = mempool entry
    tx_hash: Txid,
    tx_pos: u32,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    value: Amount,
}

#[derive(Default)]
struct Unspent {
    // mapping an outpoint to its value & confirmation height
    outpoints: HashMap<OutPoint, (Amount, usize)>,
    balance: Balance,
}

impl Unspent {
    fn build(status: &ScriptHashStatus, chain: &Chain) -> Self {
        let mut unspent = Unspent::default();
        // First, add all relevant entries' funding outputs to the outpoints' map
        status
            .confirmed_height_entries(chain)
            .for_each(|(height, entries)| entries.iter().for_each(|e| unspent.insert(e, height)));
        // Then, remove spent outpoints from the map
        status
            .confirmed_entries(chain)
            .for_each(|e| unspent.remove(e));

        unspent.balance.confirmed_balance = unspent.balance();
        // Now, do the same over the mempool (first add funding outputs, and then remove spent ones)
        status.mempool.iter().for_each(|e| unspent.insert(e, 0)); // mempool height = 0
        status.mempool.iter().for_each(|e| unspent.remove(e));

        unspent.balance.mempool_delta = unspent.balance().to_signed().unwrap()
            - unspent.balance.confirmed_balance.to_signed().unwrap();

        unspent
    }

    fn into_entries(self) -> Vec<UnspentEntry> {
        self.outpoints
            .into_iter()
            .map(|(outpoint, (value, height))| UnspentEntry {
                height,
                tx_hash: outpoint.txid,
                tx_pos: outpoint.vout,
                value,
            })
            .collect()
    }

    /// Total amount of unspent outputs
    fn balance(&self) -> Amount {
        self.outpoints
            .values()
            .fold(Amount::default(), |acc, v| acc + v.0)
    }

    fn insert(&mut self, entry: &TxEntry, height: usize) {
        for output in &entry.outputs {
            let outpoint = OutPoint {
                txid: entry.txid,
                vout: output.index,
            };
            self.outpoints.insert(outpoint, (output.value, height));
        }
    }

    fn remove(&mut self, entry: &TxEntry) {
        for spent in &entry.spent {
            self.outpoints.remove(spent);
        }
    }
}

impl ScriptHashStatus {
    /// Return non-synced (empty) status for a given script hash.
    pub fn new(scripthash: ScriptHash) -> Self {
        Self {
            scripthash,
            tip: BlockHash::all_zeros(),
            confirmed: HashMap::new(),
            mempool: Vec::new(),
            history: Vec::new(),
            statushash: None,
        }
    }

    /// Iterate through confirmed TxEntries with their corresponding block heights.
    /// Skip entries from stale blocks.
    fn confirmed_height_entries<'a>(
        &'a self,
        chain: &'a Chain,
    ) -> impl Iterator<Item = (usize, &'a [TxEntry])> + 'a {
        self.confirmed
            .iter()
            .filter_map(move |(blockhash, entries)| {
                chain
                    .get_block_height(blockhash)
                    .map(|height| (height, &entries[..]))
            })
    }

    /// Iterate through confirmed TxEntries.
    /// Skip entries from stale blocks.
    fn confirmed_entries<'a>(&'a self, chain: &'a Chain) -> impl Iterator<Item = &'a TxEntry> + 'a {
        self.confirmed_height_entries(chain)
            .flat_map(|(_height, entries)| entries)
    }

    /// Collect all funded and confirmed outpoints (as a set).
    fn confirmed_outpoints(&self, chain: &Chain) -> HashSet<OutPoint> {
        self.confirmed_entries(chain)
            .flat_map(TxEntry::funding_outpoints)
            .collect()
    }

    /// Collect unspent transaction entries
    pub(crate) fn get_unspent(&self, chain: &Chain) -> Vec<UnspentEntry> {
        Unspent::build(self, chain).into_entries()
    }

    /// Collect unspent transaction balance
    pub(crate) fn get_balance(&self, chain: &Chain) -> Balance {
        Unspent::build(self, chain).balance
    }

    /// Collect transaction history entries
    pub(crate) fn get_history(&self) -> &[HistoryEntry] {
        &self.history
    }

    /// Collect all confirmed history entries (in block order).
    fn get_confirmed_history(&self, chain: &Chain) -> Vec<HistoryEntry> {
        self.confirmed_height_entries(chain)
            .collect::<BTreeMap<usize, &[TxEntry]>>()
            .into_iter()
            .flat_map(|(height, entries)| {
                entries
                    .iter()
                    .map(move |e| HistoryEntry::confirmed(e.txid, height))
            })
            .collect()
    }

    /// Collect all mempool history entries (keeping transactions with unconfirmed parents last).
    fn get_mempool_history(&self, mempool: &Mempool) -> Vec<HistoryEntry> {
        let mut entries = self
            .mempool
            .iter()
            .filter_map(|e| mempool.get(&e.txid))
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| (e.has_unconfirmed_inputs, e.txid));
        entries
            .into_iter()
            .map(|e| HistoryEntry::unconfirmed(e.txid, e.has_unconfirmed_inputs, e.fee))
            .collect()
    }

    /// Apply `func` only on the new blocks (to be fetched via p2p interface).
    fn for_new_blocks<B, F>(&self, blockhashes: B, daemon: &Daemon, func: F) -> Result<()>
    where
        B: IntoIterator<Item = BlockHash>,
        F: FnMut(BlockHash, SerBlock),
    {
        daemon.for_blocks(
            blockhashes
                .into_iter()
                .filter(|blockhash| !self.confirmed.contains_key(blockhash)),
            func,
        )
    }

    /// Get funding and spending entries from new blocks.
    /// Also cache relevant transactions and their merkle proofs.
    fn sync_confirmed(
        &self,
        index: &Index,
        daemon: &Daemon,
        cache: &Cache,
        outpoints: &mut HashSet<OutPoint>,
        diag: &StatusSyncDiagGuard,
    ) -> Result<HashMap<BlockHash, Vec<TxEntry>>> {
        // Will be updated during the following block scans
        let mut result = HashMap::<BlockHash, HashMap<usize, TxEntry>>::new();

        diag.set_phase(
            "funding-index-lookup",
            format!("confirmed_blocks={}", self.confirmed.len()),
        );
        let funding_blockhashes = index.limit_result(index.filter_by_funding(self.scripthash))?;
        let funding_candidates = funding_blockhashes.len();
        let funding_candidate_audit = candidate_audit(index, funding_blockhashes.iter());
        log_candidate_audit(diag.id, "funding", &funding_candidate_audit);
        let funding_audit_enabled = funding_candidates >= FILTER_AUDIT_MIN_CANDIDATES;
        let funding_new_blocks = funding_blockhashes
            .iter()
            .filter(|blockhash| !self.confirmed.contains_key(*blockhash))
            .count();
        let funding_unique_new_blocks = funding_blockhashes
            .iter()
            .filter(|blockhash| !self.confirmed.contains_key(*blockhash))
            .copied()
            .collect::<HashSet<_>>()
            .len();
        if funding_audit_enabled {
            warn!(
                "[blake2b-diag] filter fetch plan status_id={} kind=funding candidate_entries={} new_entries={} unique_new_blocks={} already_confirmed_entries={}",
                diag.id,
                funding_candidates,
                funding_new_blocks,
                funding_unique_new_blocks,
                funding_candidates.saturating_sub(funding_new_blocks),
            );
        }
        if funding_candidates >= FILTER_NODE_CROSSCHECK_MIN_CANDIDATES {
            let audit_samples =
                audit_sample_candidates(index, &funding_blockhashes, &self.confirmed);
            warn!(
                "[blake2b-diag] node crosscheck plan status_id={} kind=funding samples={} v1_target={} v2_target={}",
                diag.id,
                audit_samples.len(),
                FILTER_NODE_CROSSCHECK_V1_SAMPLES,
                FILTER_NODE_CROSSCHECK_V2_SAMPLES,
            );
            daemon.for_blocks(audit_samples, |blockhash, block| {
                let header = AnyHeader::parse(&block)
                    .expect("core returned an unparseable block header during filter audit");
                let height = index.chain().get_block_height(&blockhash);
                let header_bytes = header.size();
                let electrs_matches =
                    matching_output_ordinals(&filter_block_txs_outputs(block, self.scripthash));
                match daemon.get_block_script_matches_decoded(blockhash, self.scripthash) {
                    Ok(mut node_matches) => {
                        node_matches.sort_unstable();
                        warn!(
                            "[blake2b-diag] node crosscheck status_id={} kind=funding height={:?} header_bytes={} electrs_matches={} node_matches={} agrees={} electrs_ordinals=[{}] node_ordinals=[{}]",
                            diag.id,
                            height,
                            header_bytes,
                            electrs_matches.len(),
                            node_matches.len(),
                            electrs_matches == node_matches,
                            compact_ordinals(&electrs_matches),
                            compact_ordinals(&node_matches),
                        );
                    }
                    Err(err) => warn!(
                        "[blake2b-diag] node crosscheck failed status_id={} kind=funding height={:?} header_bytes={} electrs_matches={} electrs_ordinals=[{}] error={:#}",
                        diag.id,
                        height,
                        header_bytes,
                        electrs_matches.len(),
                        compact_ordinals(&electrs_matches),
                        err,
                    ),
                }
            })?;
        }
        diag.set_phase(
            "funding-block-fetch",
            format!(
                "candidates={} new_blocks={} already_confirmed={} processed=0",
                funding_candidates,
                funding_new_blocks,
                funding_candidates.saturating_sub(funding_new_blocks),
            ),
        );
        let funding_report_every = filter_audit_report_every(funding_new_blocks);
        let funding_verify_started = Instant::now();
        let mut funding_processed = 0usize;
        let mut funding_matching_fetches = 0usize;
        let mut funding_matching_txs = 0usize;
        let mut funding_matching_outputs = 0usize;
        let mut funding_v1_matching_fetches = 0usize;
        let mut funding_v2_matching_fetches = 0usize;
        let mut funding_unknown_matching_fetches = 0usize;
        let mut funding_unique_matching_blocks = HashSet::<BlockHash>::new();
        self.for_new_blocks(funding_blockhashes, daemon, |blockhash, block| {
            let block_entries = result.entry(blockhash).or_default(); // the block may already exist

            // extract relevant funding transactions
            diag.set_phase(
                "funding-block-scan",
                format!(
                    "processed={} total={}",
                    funding_processed, funding_new_blocks
                ),
            );
            let filtered_outputs = filter_block_txs_outputs(block, self.scripthash);
            let matching_txs = filtered_outputs.len();
            let matching_outputs: usize = filtered_outputs.iter().map(|entry| entry.result.len()).sum();
            if matching_txs != 0 {
                funding_matching_fetches += 1;
                funding_matching_txs += matching_txs;
                funding_matching_outputs += matching_outputs;
                funding_unique_matching_blocks.insert(blockhash);
                match classify_candidate(index, &blockhash).1 {
                    Some(true) => funding_v2_matching_fetches += 1,
                    Some(false) => funding_v1_matching_fetches += 1,
                    None => funding_unknown_matching_fetches += 1,
                }
            }
            diag.set_phase(
                "funding-block-apply",
                format!(
                    "processed={} total={} matching_txs={}",
                    funding_processed,
                    funding_new_blocks,
                    matching_txs,
                ),
            );
            for filtered_outputs in filtered_outputs {
                cache.add_tx(filtered_outputs.txid, move || filtered_outputs.tx_bytes);
                // store funded outpoints (to check for spending later)
                outpoints.extend(make_outpoints(
                    filtered_outputs.txid,
                    &filtered_outputs.result,
                ));
                block_entries
                    .entry(filtered_outputs.pos) // the transaction may already exist
                    .or_insert_with(|| TxEntry::new(filtered_outputs.txid))
                    .outputs = filtered_outputs.result;
            }
            funding_processed += 1;
            if funding_audit_enabled
                && funding_processed % funding_report_every == 0
                && funding_processed < funding_new_blocks
            {
                let hit_rate_ppm = if funding_processed == 0 {
                    0
                } else {
                    funding_matching_fetches.saturating_mul(1_000_000) / funding_processed
                };
                warn!(
                    "[blake2b-diag] filter verify progress status_id={} kind=funding elapsed_ms={} processed={} total={} matching_fetches={} unique_matching_blocks={} nonmatching_fetches={} matching_txs={} matching_outputs={} hit_rate_ppm={} v1_matching_fetches={} v2_matching_fetches={} unknown_matching_fetches={}",
                    diag.id,
                    funding_verify_started.elapsed().as_millis(),
                    funding_processed,
                    funding_new_blocks,
                    funding_matching_fetches,
                    funding_unique_matching_blocks.len(),
                    funding_processed.saturating_sub(funding_matching_fetches),
                    funding_matching_txs,
                    funding_matching_outputs,
                    hit_rate_ppm,
                    funding_v1_matching_fetches,
                    funding_v2_matching_fetches,
                    funding_unknown_matching_fetches,
                );
            }
            diag.set_phase(
                "funding-block-fetch",
                format!(
                    "candidates={} new_blocks={} already_confirmed={} processed={}",
                    funding_candidates,
                    funding_new_blocks,
                    funding_candidates.saturating_sub(funding_new_blocks),
                    funding_processed,
                ),
            );
        })?;
        if funding_audit_enabled {
            let hit_rate_ppm = if funding_processed == 0 {
                0
            } else {
                funding_matching_fetches.saturating_mul(1_000_000) / funding_processed
            };
            warn!(
                "[blake2b-diag] filter verify complete status_id={} kind=funding elapsed_ms={} processed={} unique_new_blocks={} matching_fetches={} unique_matching_blocks={} nonmatching_fetches={} matching_txs={} matching_outputs={} hit_rate_ppm={} v1_matching_fetches={} v2_matching_fetches={} unknown_matching_fetches={}",
                diag.id,
                funding_verify_started.elapsed().as_millis(),
                funding_processed,
                funding_unique_new_blocks,
                funding_matching_fetches,
                funding_unique_matching_blocks.len(),
                funding_processed.saturating_sub(funding_matching_fetches),
                funding_matching_txs,
                funding_matching_outputs,
                hit_rate_ppm,
                funding_v1_matching_fetches,
                funding_v2_matching_fetches,
                funding_unknown_matching_fetches,
            );
        }

        diag.set_phase(
            "spending-index-lookup",
            format!("outpoints={}", outpoints.len()),
        );
        let spending_blockhashes: HashSet<BlockHash> = outpoints
            .par_iter() // use rayon for concurrent index lookups
            .flat_map_iter(|outpoint| index.filter_by_spending(*outpoint))
            .collect();
        let spending_candidates = spending_blockhashes.len();
        let spending_candidate_audit = candidate_audit(index, spending_blockhashes.iter());
        log_candidate_audit(diag.id, "spending", &spending_candidate_audit);
        let spending_audit_enabled = spending_candidates >= FILTER_AUDIT_MIN_CANDIDATES;
        let spending_new_blocks = spending_blockhashes
            .iter()
            .filter(|blockhash| !self.confirmed.contains_key(*blockhash))
            .count();
        if spending_audit_enabled {
            warn!(
                "[blake2b-diag] filter fetch plan status_id={} kind=spending outpoints={} unique_candidates={} new_blocks={} already_confirmed={}",
                diag.id,
                outpoints.len(),
                spending_candidates,
                spending_new_blocks,
                spending_candidates.saturating_sub(spending_new_blocks),
            );
        }
        diag.set_phase(
            "spending-block-fetch",
            format!(
                "outpoints={} candidates={} new_blocks={} already_confirmed={} processed=0",
                outpoints.len(),
                spending_candidates,
                spending_new_blocks,
                spending_candidates.saturating_sub(spending_new_blocks),
            ),
        );
        let spending_report_every = filter_audit_report_every(spending_new_blocks);
        let spending_verify_started = Instant::now();
        let mut spending_processed = 0usize;
        let mut spending_matching_fetches = 0usize;
        let mut spending_matching_txs = 0usize;
        let mut spending_matching_inputs = 0usize;
        let mut spending_v1_matching_fetches = 0usize;
        let mut spending_v2_matching_fetches = 0usize;
        let mut spending_unknown_matching_fetches = 0usize;
        let mut spending_unique_matching_blocks = HashSet::<BlockHash>::new();
        self.for_new_blocks(spending_blockhashes, daemon, |blockhash, block| {
            let block_entries = result.entry(blockhash).or_default(); // the block may already exist

            // extract relevant spending transactions
            diag.set_phase(
                "spending-block-scan",
                format!(
                    "processed={} total={}",
                    spending_processed, spending_new_blocks
                ),
            );
            let filtered_inputs = filter_block_txs_inputs(&block, outpoints);
            let matching_txs = filtered_inputs.len();
            let matching_inputs: usize = filtered_inputs.iter().map(|entry| entry.result.len()).sum();
            if matching_txs != 0 {
                spending_matching_fetches += 1;
                spending_matching_txs += matching_txs;
                spending_matching_inputs += matching_inputs;
                spending_unique_matching_blocks.insert(blockhash);
                match classify_candidate(index, &blockhash).1 {
                    Some(true) => spending_v2_matching_fetches += 1,
                    Some(false) => spending_v1_matching_fetches += 1,
                    None => spending_unknown_matching_fetches += 1,
                }
            }
            diag.set_phase(
                "spending-block-apply",
                format!(
                    "processed={} total={} matching_txs={}",
                    spending_processed,
                    spending_new_blocks,
                    matching_txs,
                ),
            );
            for filtered_inputs in filtered_inputs {
                cache.add_tx(filtered_inputs.txid, move || filtered_inputs.tx_bytes);
                block_entries
                    .entry(filtered_inputs.pos) // the transaction may already exist
                    .or_insert_with(|| TxEntry::new(filtered_inputs.txid))
                    .spent = filtered_inputs.result;
            }
            spending_processed += 1;
            if spending_audit_enabled
                && spending_processed % spending_report_every == 0
                && spending_processed < spending_new_blocks
            {
                let hit_rate_ppm = if spending_processed == 0 {
                    0
                } else {
                    spending_matching_fetches.saturating_mul(1_000_000) / spending_processed
                };
                warn!(
                    "[blake2b-diag] filter verify progress status_id={} kind=spending elapsed_ms={} processed={} total={} matching_fetches={} unique_matching_blocks={} nonmatching_fetches={} matching_txs={} matching_inputs={} hit_rate_ppm={} v1_matching_fetches={} v2_matching_fetches={} unknown_matching_fetches={}",
                    diag.id,
                    spending_verify_started.elapsed().as_millis(),
                    spending_processed,
                    spending_new_blocks,
                    spending_matching_fetches,
                    spending_unique_matching_blocks.len(),
                    spending_processed.saturating_sub(spending_matching_fetches),
                    spending_matching_txs,
                    spending_matching_inputs,
                    hit_rate_ppm,
                    spending_v1_matching_fetches,
                    spending_v2_matching_fetches,
                    spending_unknown_matching_fetches,
                );
            }
            diag.set_phase(
                "spending-block-fetch",
                format!(
                    "outpoints={} candidates={} new_blocks={} already_confirmed={} processed={}",
                    outpoints.len(),
                    spending_candidates,
                    spending_new_blocks,
                    spending_candidates.saturating_sub(spending_new_blocks),
                    spending_processed,
                ),
            );
        })?;
        if spending_audit_enabled {
            let hit_rate_ppm = if spending_processed == 0 {
                0
            } else {
                spending_matching_fetches.saturating_mul(1_000_000) / spending_processed
            };
            warn!(
                "[blake2b-diag] filter verify complete status_id={} kind=spending elapsed_ms={} processed={} matching_fetches={} unique_matching_blocks={} nonmatching_fetches={} matching_txs={} matching_inputs={} hit_rate_ppm={} v1_matching_fetches={} v2_matching_fetches={} unknown_matching_fetches={}",
                diag.id,
                spending_verify_started.elapsed().as_millis(),
                spending_processed,
                spending_matching_fetches,
                spending_unique_matching_blocks.len(),
                spending_processed.saturating_sub(spending_matching_fetches),
                spending_matching_txs,
                spending_matching_inputs,
                hit_rate_ppm,
                spending_v1_matching_fetches,
                spending_v2_matching_fetches,
                spending_unknown_matching_fetches,
            );
        }

        diag.set_phase(
            "confirmed-finalize",
            format!("result_blocks={} outpoints={}", result.len(), outpoints.len()),
        );

        Ok(result
            .into_iter()
            .map(|(blockhash, entries_map)| {
                let sorted_entries: Vec<TxEntry> = entries_map
                    .into_iter()
                    .collect::<BTreeMap<usize, TxEntry>>() // sort transactions by their position in a block
                    .into_values() // drop position within block
                    .collect();
                (blockhash, sorted_entries)
            })
            .collect())
    }

    /// Get funding and spending entries from current mempool.
    /// Also cache relevant transactions.
    fn sync_mempool(
        &self,
        mempool: &Mempool,
        cache: &Cache,
        outpoints: &mut HashSet<OutPoint>,
    ) -> Vec<TxEntry> {
        let mut result = HashMap::<Txid, TxEntry>::new();
        // extract relevant funding transactions
        for entry in mempool.filter_by_funding(&self.scripthash) {
            let funding_outputs = filter_outputs(&entry.tx, self.scripthash);
            assert!(!funding_outputs.is_empty());
            // store funded outpoints (to check for spending later)
            outpoints.extend(make_outpoints(entry.txid, &funding_outputs));
            result
                .entry(entry.txid) // the transaction may already exist
                .or_insert_with(|| TxEntry::new(entry.txid))
                .outputs = funding_outputs;
            cache.add_tx(entry.txid, || serialize(&entry.tx).into_boxed_slice());
        }
        for entry in outpoints
            .iter()
            .flat_map(|outpoint| mempool.filter_by_spending(outpoint))
        {
            let spent_outpoints = filter_inputs(&entry.tx, outpoints);
            assert!(!spent_outpoints.is_empty());
            result
                .entry(entry.txid) // the transaction may already exist
                .or_insert_with(|| TxEntry::new(entry.txid))
                .spent = spent_outpoints;
            cache.add_tx(entry.txid, || serialize(&entry.tx).into_boxed_slice());
        }
        result.into_values().collect()
    }

    /// Sync with currently confirmed txs and mempool, downloading non-cached transactions via p2p protocol.
    /// After a successful sync, scripthash status is updated.
    pub(crate) fn sync(
        &mut self,
        index: &Index,
        mempool: &Mempool,
        daemon: &Daemon,
        cache: &Cache,
    ) -> Result<()> {
        let diag = StatusSyncDiagGuard::new();
        diag.set_phase(
            "confirmed-outpoints",
            format!("confirmed_blocks={}", self.confirmed.len()),
        );
        let mut outpoints: HashSet<OutPoint> = self.confirmed_outpoints(index.chain());

        diag.set_phase(
            "tip-check",
            format!("confirmed_blocks={} outpoints={}", self.confirmed.len(), outpoints.len()),
        );
        let new_tip = index.chain().tip();
        if self.tip != new_tip {
            let update = self.sync_confirmed(index, daemon, cache, &mut outpoints, &diag)?;
            self.confirmed.extend(update); // add new blocks to the map
            self.tip = new_tip;
        }
        if !self.confirmed.is_empty() {
            debug!(
                "{} transactions from {} blocks",
                self.confirmed.values().map(Vec::len).sum::<usize>(),
                self.confirmed.len()
            );
        }

        diag.set_phase(
            "mempool-sync",
            format!("outpoints={} confirmed_blocks={}", outpoints.len(), self.confirmed.len()),
        );
        self.mempool = self.sync_mempool(mempool, cache, &mut outpoints);
        if !self.mempool.is_empty() {
            debug!("{} mempool transactions", self.mempool.len());
        }
        // update history entries and status hash
        diag.set_phase(
            "history-build",
            format!(
                "confirmed_blocks={} mempool_entries={}",
                self.confirmed.len(),
                self.mempool.len(),
            ),
        );
        self.history.clear();
        self.history
            .extend(self.get_confirmed_history(index.chain()));
        self.history.extend(self.get_mempool_history(mempool));

        diag.set_phase(
            "status-hash",
            format!("history_entries={}", self.history.len()),
        );
        self.statushash = compute_status_hash(&self.history);
        diag.set_phase(
            "done",
            format!(
                "history_entries={} outpoints={} confirmed_blocks={}",
                self.history.len(),
                outpoints.len(),
                self.confirmed.len(),
            ),
        );
        Ok(())
    }

    /// Get current status hash.
    pub fn statushash(&self) -> Option<StatusHash> {
        self.statushash
    }
}

fn make_outpoints(txid: Txid, outputs: &[TxOutput]) -> impl Iterator<Item = OutPoint> + '_ {
    outputs
        .iter()
        .map(move |out| OutPoint::new(txid, out.index))
}

fn filter_outputs(tx: &Transaction, scripthash: ScriptHash) -> Vec<TxOutput> {
    let outputs = tx.output.iter().zip(0u32..);
    outputs
        .filter_map(move |(txo, vout)| {
            if ScriptHash::new(&txo.script_pubkey) == scripthash {
                Some(TxOutput {
                    index: vout,
                    value: txo.value,
                })
            } else {
                None
            }
        })
        .collect()
}

fn filter_inputs(tx: &Transaction, outpoints: &HashSet<OutPoint>) -> Vec<OutPoint> {
    tx.input
        .iter()
        .filter_map(|txi| {
            if outpoints.contains(&txi.previous_output) {
                Some(txi.previous_output)
            } else {
                None
            }
        })
        .collect()
}

// See https://electrum-protocol.readthedocs.io/en/latest/protocol-basics.html#status for details
fn compute_status_hash(history: &[HistoryEntry]) -> Option<StatusHash> {
    if history.is_empty() {
        return None;
    }
    let mut engine = StatusHash::engine();
    for entry in history {
        entry.hash(&mut engine);
    }
    Some(StatusHash::from_engine(engine))
}

struct FilteredTx<T> {
    tx_bytes: Box<[u8]>,
    txid: Txid,
    pos: usize,
    result: Vec<T>,
}

fn filter_block_txs_outputs(block: SerBlock, scripthash: ScriptHash) -> Vec<FilteredTx<TxOutput>> {
    struct FindOutputs {
        scripthash: ScriptHash,
        result: Vec<FilteredTx<TxOutput>>,
        buffer: Vec<TxOutput>,
        pos: usize,
    }
    impl Visitor for FindOutputs {
        // Called after all TxOuts are visited
        fn visit_transaction(&mut self, tx: &bsl::Transaction) -> ControlFlow<()> {
            if !self.buffer.is_empty() {
                self.result.push(FilteredTx::<TxOutput> {
                    tx_bytes: tx.as_ref().into(),
                    txid: bsl_txid(tx),
                    pos: self.pos,
                    result: std::mem::take(&mut self.buffer), // clear buffer for next tx
                });
            }
            self.pos += 1;
            ControlFlow::Continue(())
        }
        // Keep only relevant outputs
        fn visit_tx_out(&mut self, vout: usize, tx_out: &bsl::TxOut) -> ControlFlow<()> {
            let current = ScriptHash::hash(tx_out.script_pubkey());
            if current == self.scripthash {
                self.buffer.push(TxOutput {
                    index: vout as u32,
                    value: Amount::from_sat(tx_out.value()),
                })
            }
            ControlFlow::Continue(())
        }
    }
    let mut find_outputs = FindOutputs {
        scripthash,
        result: vec![],
        buffer: vec![],
        pos: 0,
    };

    let header = AnyHeader::parse(&block).expect("core returned an unparseable block header");
    visit_block_txs(&block, &header, &mut find_outputs).expect("core returned invalid block");

    find_outputs.result
}

fn filter_block_txs_inputs(
    block: &SerBlock,
    outpoints: &HashSet<OutPoint>,
) -> Vec<FilteredTx<OutPoint>> {
    struct FindInputs<'a> {
        outpoints: &'a HashSet<OutPoint>,
        result: Vec<FilteredTx<OutPoint>>,
        buffer: Vec<OutPoint>,
        pos: usize,
    }

    impl Visitor for FindInputs<'_> {
        // Called after all TxIns are visited
        fn visit_transaction(&mut self, tx: &bsl::Transaction) -> ControlFlow<()> {
            if !self.buffer.is_empty() {
                self.result.push(FilteredTx::<OutPoint> {
                    tx_bytes: tx.as_ref().into(),
                    txid: bsl_txid(tx),
                    pos: self.pos,
                    result: std::mem::take(&mut self.buffer), // clear buffer for next tx
                });
            }
            self.pos += 1;
            ControlFlow::Continue(())
        }
        // Keep only relevant outpoints
        fn visit_tx_in(&mut self, _vin: usize, tx_in: &bsl::TxIn) -> ControlFlow<()> {
            let current: OutPoint = tx_in.prevout().into();
            if self.outpoints.contains(&current) {
                self.buffer.push(current);
            }
            ControlFlow::Continue(())
        }
    }

    let mut find_inputs = FindInputs {
        outpoints,
        result: vec![],
        buffer: vec![],
        pos: 0,
    };

    let header = AnyHeader::parse(block).expect("core returned an unparseable block header");
    visit_block_txs(block, &header, &mut find_inputs).expect("core returned invalid block");

    find_inputs.result
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use crate::types::ScriptHash;

    use super::HistoryEntry;
    use bitcoin::{Address, Amount};
    use bitcoin_test_data::blocks::mainnet_702861;
    use serde_json::json;

    #[test]
    fn test_txinfo_json() {
        let txid = "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b"
            .parse()
            .unwrap();
        assert_eq!(
            json!(HistoryEntry::confirmed(txid, 123456)),
            json!({"tx_hash": "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b", "height": 123456})
        );
        assert_eq!(
            json!(HistoryEntry::unconfirmed(txid, true, Amount::from_sat(123))),
            json!({"tx_hash": "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b", "height": -1, "fee": 123})
        );
        assert_eq!(
            json!(HistoryEntry::unconfirmed(
                txid,
                false,
                Amount::from_sat(123)
            )),
            json!({"tx_hash": "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b", "height": 0, "fee": 123})
        );
    }

    #[test]
    fn test_find_outputs() {
        let block = mainnet_702861().to_vec();

        let addr = Address::from_str("1A9MXXG26vZVySrNNytQK1N8bX42ZuJ6Ax")
            .unwrap()
            .assume_checked();
        let scripthash = ScriptHash::new(&addr.script_pubkey());

        let result = &super::filter_block_txs_outputs(block, scripthash)[0];
        assert_eq!(
            result.txid.to_string(),
            "7bcdcb44422da5a99daad47d6ba1c3d6f2e48f961a75e42c4fa75029d4b0ef49"
        );
        assert_eq!(result.pos, 8);
        assert_eq!(result.result[0].index, 0);
        assert_eq!(result.result[0].value.to_sat(), 709503);
    }

    #[test]
    fn test_find_inputs() {
        let block = mainnet_702861().to_vec();
        let outpoint = bitcoin::OutPoint::from_str(
            "cc135e792b37a9c4ffd784f696b1e38bd1197f8e67ae1f96c9f13e4618b91866:3",
        )
        .unwrap();
        let mut outpoints = HashSet::new();
        outpoints.insert(outpoint);

        let result = &super::filter_block_txs_inputs(&block, &outpoints)[0];
        assert_eq!(
            result.txid.to_string(),
            "7bcdcb44422da5a99daad47d6ba1c3d6f2e48f961a75e42c4fa75029d4b0ef49"
        );
        assert_eq!(result.pos, 8);
        assert_eq!(result.result[0], outpoint);
    }
}
