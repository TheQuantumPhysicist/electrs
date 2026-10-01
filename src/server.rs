use anyhow::{Context, Result};
use crossbeam_channel::{select, unbounded, Sender};
use rayon::prelude::*;

use std::{
    collections::hash_map::HashMap,
    io::{BufRead, BufReader, Write},
    iter::once,
    net::{Shutdown, TcpListener, TcpStream},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use crate::{
    config::Config,
    electrum::{Client, Rpc},
    metrics::{self, Metrics},
    signals::ExitError,
    thread::spawn,
};

struct ServerDiagState {
    phase: &'static str,
    since: Instant,
    detail: String,
    peer_activity: HashMap<usize, PeerDiagActivity>,
}

struct PeerDiagActivity {
    stage: &'static str,
    since: Instant,
    detail: String,
}

static SERVER_DIAG: OnceLock<Mutex<ServerDiagState>> = OnceLock::new();

fn server_diag() -> &'static Mutex<ServerDiagState> {
    SERVER_DIAG.get_or_init(|| {
        Mutex::new(ServerDiagState {
            phase: "startup",
            since: Instant::now(),
            detail: String::new(),
            peer_activity: HashMap::new(),
        })
    })
}

fn set_server_phase(phase: &'static str, detail: String) {
    let mut state = server_diag().lock().unwrap_or_else(|err| err.into_inner());
    state.phase = phase;
    state.since = Instant::now();
    state.detail = detail;
    if phase != "notify-peers" {
        state.peer_activity.clear();
    }
}

fn set_peer_activity(peer_id: usize, stage: &'static str, detail: String) {
    server_diag()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .peer_activity
        .insert(
            peer_id,
            PeerDiagActivity {
                stage,
                since: Instant::now(),
                detail,
            },
        );
}

fn clear_peer_activity(peer_id: usize) {
    server_diag()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .peer_activity
        .remove(&peer_id);
}

pub(crate) fn diagnostic_server_state() -> String {
    let state = server_diag().lock().unwrap_or_else(|err| err.into_inner());
    let mut peers: Vec<String> = state
        .peer_activity
        .iter()
        .map(|(peer_id, activity)| {
            format!(
                "peer={} stage={} elapsed_ms={} {}",
                peer_id,
                activity.stage,
                activity.since.elapsed().as_millis(),
                activity.detail,
            )
        })
        .collect();
    peers.sort();
    if peers.len() > 8 {
        peers.truncate(8);
        peers.push("more-peers-omitted".to_owned());
    }
    format!(
        "phase={} elapsed_ms={} detail=[{}] active_peers=[{}] subscribe_state={} status_state={} block_source_state={} cache_state={}",
        state.phase,
        state.since.elapsed().as_millis(),
        state.detail,
        peers.join("; "),
        crate::electrum::diagnostic_subscribe_state(),
        crate::status::diagnostic_status_state(),
        crate::daemon::diagnostic_block_source_state(),
        crate::cache::diagnostic_cache_state(),
    )
}

struct Peer {
    id: usize,
    client: Client,
    stream: TcpStream,
}

impl Peer {
    fn new(id: usize, stream: TcpStream) -> Self {
        let client = Client::default();
        Self { id, client, stream }
    }

    fn send(&mut self, values: Vec<String>) -> Result<()> {
        for mut value in values {
            debug!("{}: send {}", self.id, value);
            value += "\n";
            self.stream
                .write_all(value.as_bytes())
                .with_context(|| format!("failed to send response: {:?}", value))?;
        }
        Ok(())
    }

    fn disconnect(self) {
        if let Err(e) = self.stream.shutdown(Shutdown::Both) {
            warn!("{}: failed to shutdown TCP connection {}", self.id, e)
        }
    }
}

pub fn run() -> Result<()> {
    let result = serve();
    if let Err(e) = &result {
        for cause in e.chain() {
            if cause.downcast_ref::<ExitError>().is_some() {
                info!("electrs stopped: {:?}", e);
                return Ok(());
            }
        }
    }
    result.context("electrs failed")
}

fn serve() -> Result<()> {
    let config = Config::from_args();
    let metrics = Metrics::new(config.monitoring_addr)?;

    let (server_tx, server_rx) = unbounded();
    if !config.disable_electrum_rpc {
        let listener = TcpListener::bind(config.electrum_rpc_addr)?;
        info!("serving Electrum RPC on {}", listener.local_addr()?);
        spawn("accept_loop", || accept_loop(listener, server_tx)); // detach accepting thread
    };

    let server_batch_size = metrics.histogram_vec(
        "server_batch_size",
        "# of server events handled in a single batch",
        "type",
        metrics::default_size_buckets(),
    );
    let duration = metrics.histogram_vec(
        "server_loop_duration",
        "server loop duration",
        "step",
        metrics::default_duration_buckets(),
    );
    let mut rpc = Rpc::new(&config, metrics)?;

    let new_block_rx = rpc.new_block_notification();
    let mut peers = HashMap::<usize, Peer>::new();
    let mut last_sync = Instant::now();
    let mut sync_starved = false;
    loop {
        if !server_rx.is_empty()
            && last_sync.elapsed() >= Duration::from_secs(30)
            && !sync_starved
        {
            warn!(
                "[blake2b-diag] sync starvation entered since_last_sync_ms={} queued_server_events={} peers={}",
                last_sync.elapsed().as_millis(),
                server_rx.len(),
                peers.len(),
            );
            sync_starved = true;
        }

        // initial sync and compaction may take a few hours
        while server_rx.is_empty() {
            if sync_starved {
                info!(
                    "[blake2b-diag] sync starvation recovered after_ms={} peers={}",
                    last_sync.elapsed().as_millis(),
                    peers.len(),
                );
                sync_starved = false;
            }
            set_server_phase(
                "sync",
                format!(
                    "queued_server_events={} peers={}",
                    server_rx.len(),
                    peers.len(),
                ),
            );
            let sync_started = Instant::now();
            let done = duration.observe_duration("sync", || rpc.sync().context("sync failed"))?; // sync a batch of blocks
            let sync_elapsed = sync_started.elapsed();
            last_sync = Instant::now();
            if sync_elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow sync elapsed_ms={} queued_server_events={} peers={}",
                    sync_elapsed.as_millis(),
                    server_rx.len(),
                    peers.len(),
                );
            }
            set_server_phase("notify-peers", peer_summary(&peers));
            let notify_started = Instant::now();
            peers = duration.observe_duration("notify", || notify_peers(&rpc, peers)); // peers are disconnected on error
            let notify_elapsed = notify_started.elapsed();
            if notify_elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow peer notification pass elapsed_ms={} peers={} queued_server_events={}",
                    notify_elapsed.as_millis(),
                    peers.len(),
                    server_rx.len(),
                );
            }
            if !done {
                continue; // more blocks to sync
            }
            if config.sync_once {
                return Ok(()); // exit after initial sync is done
            }
            break;
        }
        set_server_phase(
            "select-wait",
            format!(
                "queued_server_events={} peers={}",
                server_rx.len(),
                peers.len(),
            ),
        );
        duration.observe_duration("select", || -> Result<()> {
            select! {
                // Handle signals for graceful shutdown
                recv(rpc.signal().receiver()) -> result => {
                    result.context("signal channel disconnected")?;
                    rpc.signal().exit_flag().poll().context("RPC server interrupted")?;
                },
                // Handle new blocks' notifications
                recv(new_block_rx) -> result => match result {
                    Ok(_) => {
                        let pending = server_rx.len();
                        set_server_phase(
                            "block-wakeup",
                            format!(
                                "queued_server_events={} peers={} since_last_sync_ms={}",
                                pending,
                                peers.len(),
                                last_sync.elapsed().as_millis(),
                            ),
                        );
                        if pending == 0 {
                            info!(
                                "[blake2b-diag] block wakeup consumed since_last_sync_ms={} peers={}",
                                last_sync.elapsed().as_millis(),
                                peers.len(),
                            );
                        } else {
                            warn!(
                                "[blake2b-diag] block wakeup consumed but sync deferred queued_server_events={} since_last_sync_ms={} peers={}",
                                pending,
                                last_sync.elapsed().as_millis(),
                                peers.len(),
                            );
                        }
                    }, // sync and update
                    Err(_) => {
                        info!("disconnected from bitcoind");
                        return Ok(());
                    }
                },
                // Handle Electrum RPC requests
                recv(server_rx) -> event => {
                    let first = once(event.context("server disconnected")?);
                    let rest = server_rx.iter().take(server_rx.len());
                    let events: Vec<Event> = first.chain(rest).collect();
                    server_batch_size.observe("recv", events.len() as f64);
                    let event_count = events.len();
                    set_server_phase(
                        "electrum-events",
                        format!(
                            "events={} queued_after_drain={} peers={}",
                            event_count,
                            server_rx.len(),
                            peers.len(),
                        ),
                    );
                    let handle_started = Instant::now();
                    duration.observe_duration("handle", || handle_events(&rpc, &mut peers, events));
                    let handle_elapsed = handle_started.elapsed();
                    if handle_elapsed >= Duration::from_secs(10) {
                        warn!(
                            "[blake2b-diag] slow Electrum event batch events={} elapsed_ms={} queued_after={} peers={}",
                            event_count,
                            handle_elapsed.as_millis(),
                            server_rx.len(),
                            peers.len(),
                        );
                    }
                },
                default(config.wait_duration) => (), // sync and update
            };
            Ok(())
        })?;
    }
}

fn notify_peers(rpc: &Rpc, peers: HashMap<usize, Peer>) -> HashMap<usize, Peer> {
    peers
        .into_par_iter()
        .filter_map(|(_, mut peer)| {
            let result = notify_peer(rpc, &mut peer);
            clear_peer_activity(peer.id);
            match result {
                Ok(()) => Some((peer.id, peer)),
                Err(e) => {
                    error!("failed to notify peer {}: {:#}", peer.id, e);
                    peer.disconnect();
                    None
                }
            }
        })
        .collect()
}

fn notify_peer(rpc: &Rpc, peer: &mut Peer) -> Result<()> {
    let summary = client_summary(&peer.client);
    set_peer_activity(peer.id, "update-client", summary.clone());
    let notifications = rpc
        .update_client(&mut peer.client)
        .context("failed to generate notifications")?;
    set_peer_activity(
        peer.id,
        "send-notifications",
        format!(
            "{} notifications={} response_bytes={}",
            summary,
            notifications.len(),
            notifications.iter().map(String::len).sum::<usize>(),
        ),
    );
    peer.send(notifications)
        .context("failed to send notifications")
}

struct Event {
    peer_id: usize,
    msg: Message,
}

enum Message {
    New(TcpStream),
    Request(String),
    Done,
}

fn handle_events(rpc: &Rpc, peers: &mut HashMap<usize, Peer>, events: Vec<Event>) {
    let mut events_by_peer = HashMap::<usize, Vec<Message>>::new();
    events
        .into_iter()
        .for_each(|e| events_by_peer.entry(e.peer_id).or_default().push(e.msg));
    for (peer_id, messages) in events_by_peer {
        handle_peer_events(rpc, peers, peer_id, messages);
    }
}

fn handle_peer_events(
    rpc: &Rpc,
    peers: &mut HashMap<usize, Peer>,
    peer_id: usize,
    messages: Vec<Message>,
) {
    let mut lines = vec![];
    let mut done = false;
    for msg in messages {
        match msg {
            Message::New(stream) => {
                debug!("{}: connected", peer_id);
                peers.insert(peer_id, Peer::new(peer_id, stream));
            }
            Message::Request(line) => lines.push(line),
            Message::Done => {
                done = true;
                break;
            }
        }
    }
    let result = match peers.get_mut(&peer_id) {
        Some(peer) => {
            let methods = request_method_summary(&lines);
            set_server_phase(
                "peer-request",
                format!(
                    "peer={} lines={} methods={} {}",
                    peer_id,
                    lines.len(),
                    methods,
                    client_summary(&peer.client),
                ),
            );
            let request_started = Instant::now();
            let responses = rpc.handle_requests(&mut peer.client, &lines);
            let request_elapsed = request_started.elapsed();
            if request_elapsed >= Duration::from_secs(10) {
                warn!(
                    "[blake2b-diag] slow peer request peer={} lines={} elapsed_ms={} methods={}",
                    peer_id,
                    lines.len(),
                    request_elapsed.as_millis(),
                    methods,
                );
            }
            set_server_phase(
                "peer-response-send",
                format!(
                    "peer={} responses={} response_bytes={} {}",
                    peer_id,
                    responses.len(),
                    responses.iter().map(String::len).sum::<usize>(),
                    client_summary(&peer.client),
                ),
            );
            peer.send(responses)
        }
        None => return, // unknown peer
    };
    if let Err(e) = result {
        error!("{}: disconnecting due to {}", peer_id, e);
        peers.remove(&peer_id).unwrap().disconnect();
    } else if done {
        peers.remove(&peer_id); // already disconnected, just remove from peers' map
    }
}

fn client_summary(client: &Client) -> String {
    let (header_subscribed, scripthashes, negotiated) = client.diagnostic_state();
    format!(
        "header_subscribed={} scripthashes={} protocol={}",
        header_subscribed,
        scripthashes,
        negotiated.unwrap_or("none"),
    )
}

fn peer_summary(peers: &HashMap<usize, Peer>) -> String {
    let total_scripthashes = peers
        .values()
        .map(|peer| peer.client.diagnostic_state().1)
        .sum::<usize>();
    let header_subscribers = peers
        .values()
        .filter(|peer| peer.client.diagnostic_state().0)
        .count();
    format!(
        "peers={} header_subscribers={} total_scripthashes={}",
        peers.len(),
        header_subscribers,
        total_scripthashes,
    )
}

fn request_method_summary(lines: &[String]) -> String {
    fn collect(value: &serde_json::Value, methods: &mut Vec<String>) {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    collect(value, methods);
                }
            }
            serde_json::Value::Object(object) => {
                if let Some(method) = object.get("method").and_then(|value| value.as_str()) {
                    if !methods.iter().any(|seen| seen == method) && methods.len() < 8 {
                        methods.push(method.to_owned());
                    }
                }
            }
            _ => {}
        }
    }

    let mut methods = Vec::new();
    for line in lines {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            collect(&value, &mut methods);
        }
    }
    if methods.is_empty() {
        "unknown".to_owned()
    } else {
        methods.join(",")
    }
}

fn accept_loop(listener: TcpListener, server_tx: Sender<Event>) -> Result<()> {
    for (peer_id, conn) in listener.incoming().enumerate() {
        let stream = conn.context("failed to accept")?;
        let tx = server_tx.clone();
        spawn("recv_loop", move || {
            let result = recv_loop(peer_id, &stream, tx);
            if let Err(e) = stream.shutdown(Shutdown::Read) {
                warn!("{}: failed to shutdown TCP receiving {}", peer_id, e)
            }
            result
        });
    }
    Ok(())
}

fn recv_loop(peer_id: usize, stream: &TcpStream, server_tx: Sender<Event>) -> Result<()> {
    let msg = Message::New(stream.try_clone()?);
    server_tx.send(Event { peer_id, msg })?;

    let mut first_line = true;
    for line in BufReader::new(stream).lines() {
        if let Err(e) = &line {
            if first_line && e.kind() == std::io::ErrorKind::InvalidData {
                warn!("InvalidData on first line may indicate client attempted to connect using SSL when server expects unencrypted communication.")
            }
        }
        let line = line.with_context(|| format!("{}: recv failed", peer_id))?;
        debug!("{}: recv {}", peer_id, line);
        let msg = Message::Request(line);
        server_tx.send(Event { peer_id, msg })?;
        first_line = false;
    }

    debug!("{}: disconnected", peer_id);
    let msg = Message::Done;
    server_tx.send(Event { peer_id, msg })?;
    Ok(())
}
