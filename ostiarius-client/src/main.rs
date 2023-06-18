//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use anyhow::Context;
use gumdrop::Options;
use ostiarius_core::{
    crypto::password::PasswordProvider, utils::insert_password, Error, Requester,
};
use reqwest::blocking;
use uuid::Uuid;

#[derive(Debug, Options)]
struct ClientOptions {
    #[options(help = "Print this help message and exit")]
    help: bool,
    #[options(help = "Print program version and exit")]
    version: bool,
    #[options(help = "Set client name")]
    name: Option<String>,
    #[options(help = "URI of server private key", meta = "URI")]
    priv_key: Option<String>,
    #[options(help = "Path to server public key")]
    server_pub_key: Option<String>,
    #[options(
        help = "Password provider",
        meta = "PROVIDER",
        long = "password",
        short = "S"
    )]
    password_provider: Option<String>,
    #[options(free)]
    url: String,
    #[options(free)]
    command: String,
}

fn main() -> anyhow::Result<()> {
    let options = ClientOptions::parse_args_default_or_exit();
    if options.version {
        println!("ostiarius-client {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    let name = match options.name {
        Some(name) => name,
        None => hostname::get()
            .context("failed to get hostname")?
            .into_string()
            .map_err(Error::InvalidPath)
            .context("failed to convert hostname")?,
    };
    let server_pub_key = options
        .server_pub_key
        .unwrap_or_else(|| "server.pubkey.pem".to_string());
    let mut path = std::env::current_dir().context("failed to get current directory")?;
    path.push("server.privkey.pem");
    let client_priv_key = options
        .priv_key
        .unwrap_or(format!("file://{}", path.display()));
    let password_provider = match options.password_provider {
        Some(provider) => provider.parse()?,
        None => PasswordProvider::Prompt,
    };
    let password = password_provider
        .provide()
        .context("failed to get password")?;
    let client_priv_key = insert_password(&password, &client_priv_key)?;
    let requester =
        Requester::new(&client_priv_key, server_pub_key).context("failed to create requester")?;
    let request = requester
        .make(&name, &options.command)
        .context("failed to make request")?;
    let client = blocking::Client::new();
    let url = format!("{}/api/v1/authorizations", options.url);
    let res = client
        .post(&url)
        .json(&request)
        .send()
        .context("failed to post authorization request")?;
    if !res.status().is_success() {
        eprintln!("Forbidden to execute command");
        std::process::exit(2);
    }
    let uuid = res.json::<Uuid>().context("failed to decode response")?;
    let authorization = client
        .get(format!("{}/{}", &url, &uuid))
        .send()
        .context("failed to get authorization")?;
    let approved = requester
        .check(&authorization.json()?)
        .context("failed to check authorization")?;
    if !approved {
        eprintln!("Authorization mismatch");
        std::process::exit(3);
    }
    let args = options
        .command
        .split_ascii_whitespace()
        .collect::<Vec<&str>>();
    let status = std::process::Command::new(args[0])
        .args(args[1..].iter())
        .status()
        .context("failed to execute command")?;
    if !status.success() {
        eprintln!("Command failed");
        std::process::exit(4);
    }
    Ok(())
}
