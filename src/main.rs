use anyhow::Result;
use futures::stream::StreamExt;
use s2n_quic::provider::datagram::default::Endpoint;
use s2n_quic::Client;
use s2n_quic::Server;
use s2n_quic_tls::Client as TlsClient;
use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{env, fmt};
use tokio::net::lookup_host;
use tokio::time::{self};

///
#[derive(Debug)]
struct Parameters {
    pub server_host: String,
    pub server_serv: String,
    pub recv_timeout: u64,
    pub ca_cert_pem: String,
    pub datagram_queue_len: usize,
}

impl Parameters {
    fn init() -> Self {
        let server_host = env::var("SERVER_HOST").unwrap();
        let server_serv = env::var("SERVER_SERV").unwrap();

        let recv_timeout = match env::var("RECV_TIMEOUT") {
            Ok(value) => match value.parse::<u64>() {
                Ok(num) => num,
                Err(_e) => 180,
            },
            Err(_e) => 180,
        };

        let ca_cert_pem = match env::var("CA") {
            Ok(value) => value,
            Err(_) => String::from("ca.crt"),
        };

        let datagram_queue_len = match env::var("DATAGRAM_QUEUE_LEN") {
            Ok(value) => match value.parse::<usize>() {
                Ok(num) => num,
                Err(_e) => 2048,
            },
            Err(_e) => 2048,
        };

        let mtu_size = match env::var("MTU") {
            Ok(value) => match value.parse::<usize>() {
                Ok(num) => num,
                Err(_e) => 1320,
            },
            Err(_e) => 1320,
        };
        let mtu_size = format!("{}", mtu_size);

        Parameters {
            server_host: server_host,
            server_serv: server_serv,
            recv_timeout: recv_timeout,
            ca_cert_pem: ca_cert_pem,
            datagram_queue_len: datagram_queue_len,
        }
    }
}

fn create_tls_config(ca_certs: Vec<String>) -> Result<TlsClient> {
    let mut tls_client_builder = TlsClient::builder();
    for pem_cert in ca_certs {
        tls_client_builder = tls_client_builder.with_certificate(pem_cert.as_bytes())?;
    }
    let tls_provider = tls_client_builder.build()?;
    Ok(tls_provider)
}

///
async fn run_client(running: Arc<AtomicBool>) -> Result<()> {
    let params = Parameters::init();
    log::trace!("parameters: {:?}", params);

    let datagram_provider = Endpoint::builder()
        .with_send_capacity(params.datagram_queue_len)?
        .build()?;

    let tls = create_tls_config(vec![])?;
    let client = Client::builder()
        .with_tls(tls)?
        .with_io("0.0.0.0:0")?
        .with_datagram(datagram_provider)?
        .start()?;

    let addrs = lookup_host(format!("{}:{}", params.server_host, params.server_serv));
    let addr: SocketAddr = addrs.await?.next().unwrap();
    let connect = s2n_quic::client::Connect::new(addr).with_server_name(params.server_host.clone());
    let (connection, stream) = match client.connect(connect).await {
        Ok(mut c) => {
            c.keep_alive(true)?;
            let stream = c.open_bidirectional_stream().await?;
            (Some(c), stream)
        }
        Err(e) => {
            return Err(anyhow::Error::from(e));
        }
    };

    // コネクションの切断
    connection.close(0u32.into());
    Ok(())
}

/// This is main function of tokio
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let res = run_client(running.clone()).await;
    match res {
        Err(e) => {
            log::error!("error occurred e={}", e);
        }
        _ => {}
    }
    Ok(())
}
