//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::{Error, Result};
use chrono::{DateTime, Utc};
use openssl::{
    base64,
    pkey::{Private, Public},
    rsa::{Padding, Rsa},
};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use toml;
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct Request {
    pub name: String,
    pub command: String,
    pub challenge: String,
}

#[derive(Debug)]
pub struct Requester {
    checker_pub_key: Rsa<Public>,
    token: [u8; 32],
}

impl Requester {
    pub fn new<P: AsRef<Path>>(checker_pub_key_path: P) -> Result<Self> {
        let checker_pub_key = std::fs::read(checker_pub_key_path)?;
        let checker_pub_key = Rsa::public_key_from_pem(&checker_pub_key)?;
        let mut rng = rand::thread_rng();
        let mut token = [0u8; 32];
        rng.fill(&mut token);
        let requester = Requester {
            checker_pub_key,
            token,
        };
        Ok(requester)
    }

    pub fn make(&self, name: &str, command: &str) -> Result<Request> {
        let request = Request {
            name: name.to_string(),
            command: command.to_string(),
            challenge: self.make_challenge()?,
        };
        Ok(request)
    }

    fn make_challenge(&self) -> Result<String> {
        let mut challenge: Vec<u8> = vec![0; self.checker_pub_key.size() as usize];
        let _ = self
            .checker_pub_key
            .public_encrypt(&self.token, &mut challenge, Padding::PKCS1)?;
        Ok(base64::encode_block(&challenge))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizedClient {
    pub name: String,
    pub pub_key: String,
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Authorizations {
    clients: Vec<AuthorizedClient>,
}

impl Authorizations {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let authorizations = toml::from_str(&contents)?;
        Ok(authorizations)
    }

    pub fn clients(&self) -> &Vec<AuthorizedClient> {
        &self.clients
    }
}

#[derive(Debug, Clone)]
pub struct Checker {
    authorizations: Authorizations,
    priv_key: Rsa<Private>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Authorization {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub command: String,
    pub token: String,
}

impl Checker {
    pub fn new<P: AsRef<Path>>(priv_key_path: P, authorizations: Authorizations) -> Result<Self> {
        let priv_key: Vec<u8> = std::fs::read(priv_key_path)?;
        let priv_key = Rsa::private_key_from_pem(&priv_key)?;
        let checker = Checker {
            authorizations,
            priv_key,
        };
        Ok(checker)
    }

    pub fn check(&self, request: &Request) -> Result<Authorization> {
        let data = base64::decode_block(&&request.challenge)?;
        let mut challenge: Vec<u8> = vec![0; self.priv_key.size() as usize];
        let size = self
            .priv_key
            .private_decrypt(&data, &mut challenge, Padding::PKCS1)?;
        let client = self
            .authorizations
            .clients()
            .iter()
            .filter(|client| {
                client.name == request.name
                    && client.commands.iter().any(|cmd| cmd == &request.command)
            })
            .next()
            .ok_or(Error::Unauthorized)?;
        let pub_key: Rsa<Public> = Rsa::public_key_from_pem(&client.pub_key.as_bytes())?;
        let mut token: Vec<u8> = vec![0; pub_key.size() as usize];
        let _size = pub_key.public_encrypt(&challenge[0..size], &mut token, Padding::PKCS1)?;
        let authorization = Authorization {
            id: Uuid::new_v4(),
            timestamp: chrono::offset::Utc::now(),
            name: request.name.clone(),
            command: request.command.clone(),
            token: base64::encode_block(&token),
        };
        Ok(authorization)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_checker() -> Result<Checker> {
        let data_dir: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "tests"].iter().collect();
        let path = data_dir.join("authorizations.toml");
        let authorizations = Authorizations::from_file(path)?;
        let priv_key = data_dir.join("server.privkey.pem");
        Checker::new(priv_key, authorizations)
    }

    fn create_requester() -> Result<Requester> {
        let data_dir: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "tests"].iter().collect();
        let path = data_dir.join("server.pubkey.pem");
        Requester::new(path)
    }

    #[test]
    fn make_and_check() {
        let checker = create_checker();
        assert!(checker.is_ok());
        let requester = create_requester();
        assert!(requester.is_ok());
        let request = requester.unwrap().make("Client 1", "date");
        assert!(request.is_ok());
        let authorization = checker.unwrap().check(&request.unwrap());
        assert!(authorization.is_ok());
    }
}
