//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::{crypto::PrivateKey, Result};
use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct FileRsaPrivateKey {
    inner: Rsa<Private>,
}

impl FileRsaPrivateKey {
    pub fn from_pem_file<P: AsRef<Path>>(priv_key_path: P) -> Result<Self> {
        let priv_key: Vec<u8> = std::fs::read(priv_key_path)?;
        let inner = Rsa::private_key_from_pem(&priv_key)?;
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
