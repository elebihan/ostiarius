//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use anyhow::Context;
use gumdrop::Options;
use ostiarius_core::{Authorizations, Checker};
use ostiarius_server::{config::Config, http, models};
use std::net::IpAddr;

#[derive(Debug, Options)]
pub struct ServerOptions {
    #[options(help = "Print this help message and exit")]
    pub help: bool,
    #[options(help = "Print program version and exit")]
    pub version: bool,
    #[options(help = "Address to bind to")]
    pub address: Option<String>,
    #[options(help = "Port to use")]
    pub port: Option<u16>,
    #[options(help = "Path to authorizations file", meta = "FILE")]
    pub authorizations: Option<String>,
    #[options(help = "URI of server private key", meta = "URI")]
    priv_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = ServerOptions::parse_args_default_or_exit();
    if options.version {
        println!("ostracius-server {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    let address = options
        .address
        .unwrap_or("127.0.0.1".to_string())
        .parse::<IpAddr>()
        .context("Failed to parse IP address")?;
    let port = options.port.unwrap_or(3000);
    let mut path = std::env::current_dir().context("failed to get current directory")?;
    path.push("server.pubkey.pem");
    let priv_key = options
        .priv_key
        .unwrap_or(format!("file://{}", path.display()));
    let authorizations = options
        .authorizations
        .unwrap_or("authorizations.toml".to_string());
    let authorizations =
        Authorizations::from_file(authorizations).context("failed to load authorizations")?;
    let checker = Checker::new(&priv_key, authorizations).context("failed to create checker")?;
    let config = Config {
        address,
        port,
        checker,
    };
    let db = models::Database::default();
    http::serve(config, db).await
}
