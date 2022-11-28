//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

mod openssl;
mod pkcs11;

use crate::{
    crypto::{openssl::FileRsaPrivateKey, pkcs11::Pkcs11RsaPrivateKey},
    Error, Result,
};
use url::Url;

pub trait PrivateKey {
    fn decrypt(&self, from: &[u8], to: &mut [u8]) -> Result<usize>;
    fn size(&self) -> usize;
}

#[derive(Debug, Clone)]
pub enum RsaPrivateKey {
    File(FileRsaPrivateKey),
    Pkcs11(Pkcs11RsaPrivateKey),
}

impl RsaPrivateKey {
    pub fn from_uri(uri: &str) -> Result<RsaPrivateKey> {
        let url = Url::parse(uri)?;
        let key = match url.scheme() {
            "file" => {
                let key = FileRsaPrivateKey::new(&url)?;
                RsaPrivateKey::File(key)
            }
            "pkcs11" => {
                let key = Pkcs11RsaPrivateKey::new(&url)?;
                RsaPrivateKey::Pkcs11(key)
            }
            _ => return Err(Error::InvalidUri(uri.into())),
        };
        Ok(key)
    }
}

impl PrivateKey for RsaPrivateKey {
    fn decrypt(&self, from: &[u8], to: &mut [u8]) -> Result<usize> {
        match self {
            RsaPrivateKey::File(key) => key.decrypt(from, to),
            RsaPrivateKey::Pkcs11(key) => key.decrypt(from, to),
        }
    }
    fn size(&self) -> usize {
        match self {
            RsaPrivateKey::File(key) => key.size(),
            RsaPrivateKey::Pkcs11(key) => key.size(),
        }
    }
}
