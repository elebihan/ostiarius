//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::{crypto::PrivateKey, Error, Result};
use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};
use url::Url;

#[derive(Debug, Clone)]
pub struct FileRsaPrivateKey {
    inner: Rsa<Private>,
}

impl FileRsaPrivateKey {
    pub fn new(url: &Url) -> Result<Self> {
        let password = url
            .query_pairs()
            .find_map(|(k, v)| if k == "password" { Some(v) } else { None });
        let path = url
            .to_file_path()
            .map_err(|_| Error::InvalidUri(url.to_string()))?;
        let priv_key: Vec<u8> = std::fs::read(path)?;
        let inner = match password {
            Some(password) => Rsa::private_key_from_pem_passphrase(&priv_key, password.as_bytes())?,
            None => Rsa::private_key_from_pem(&priv_key)?,
        };
        Ok(FileRsaPrivateKey { inner })
    }
}

impl PrivateKey for FileRsaPrivateKey {
    fn decrypt(&self, from: &[u8], to: &mut [u8]) -> Result<usize> {
        let size = self.inner.private_decrypt(from, to, Padding::PKCS1)?;
        Ok(size)
    }
    fn size(&self) -> usize {
        self.inner.size() as usize
    }
}
