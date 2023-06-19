//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use super::url::Pkcs11Url;
use crate::{crypto::PrivateKey, Error, Result};

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectHandle},
    session::{Session, SessionFlags, UserType},
};
use url::Url;

#[derive(Debug, Clone)]
pub struct Pkcs11RsaPrivateKey {
    url: Pkcs11Url,
    pkcs11: Pkcs11,
    size: usize,
}

impl Pkcs11RsaPrivateKey {
    pub fn new(url: &Url) -> Result<Self> {
        let url = Pkcs11Url::try_from(url)?;
        let pkcs11 = Pkcs11::new(url.module_path())?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;
        let size = Self::get_size(&pkcs11, &url)?;
        Ok(Pkcs11RsaPrivateKey { url, pkcs11, size })
    }

    fn open_session(pkcs11: &Pkcs11, url: &Pkcs11Url) -> Result<Session> {
        let slots = pkcs11.get_slots_with_initialized_token()?;
        if slots.is_empty() {
            return Err(Error::InvalidKey("No PKCS#11 token found".to_string()));
        }

        let mut flags = SessionFlags::new();
        flags.set_rw_session(false);
        flags.set_serial_session(true);
        let session = pkcs11.open_session_no_callback(slots[0], flags)?;
        session.login(UserType::User, Some(url.pin()))?;
        Ok(session)
    }

    fn acquire(pkcs11: &Pkcs11, url: &Pkcs11Url) -> Result<(Session, ObjectHandle)> {
        let session = Self::open_session(pkcs11, url)?;
        let key_template = vec![
            Attribute::Label(url.object().as_bytes().to_vec()),
            Attribute::Private(true),
            Attribute::Sign(true),
        ];
        let keys = session.find_objects(&key_template)?;
        if keys.is_empty() {
            return Err(Error::InvalidKey("No such PKCS#11 key".to_string()));
        }
        Ok((session, keys[0]))
    }

    fn get_size(pkcs11: &Pkcs11, url: &Pkcs11Url) -> Result<usize> {
        let (session, key) = Self::acquire(pkcs11, url)?;
        let attr_types = vec![AttributeType::Modulus];
        let attrs = session.get_attributes(key, &attr_types)?;
        if attrs.is_empty() {
            return Err(Error::InvalidKey("No modulus".to_string()));
        }
        if let Attribute::Modulus(modulus) = &attrs[0] {
            Ok(modulus.len())
        } else {
            Err(Error::InvalidKey("Unexpected key attribute".to_string()))
        }
    }
}

impl PrivateKey for Pkcs11RsaPrivateKey {
    fn decrypt(&self, from: &[u8], to: &mut [u8]) -> Result<usize> {
        let (session, key) = Self::acquire(&self.pkcs11, &self.url)?;
        let data = session.decrypt(&Mechanism::RsaPkcs, key, from)?;
        let limit = std::cmp::min(to.len(), data.len());
        to[..limit].copy_from_slice(&data[..limit]);
        Ok(limit)
    }

    fn size(&self) -> usize {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVALID_URL_NO_OBJECT: &str =
        "pkcs11:token=Ostiarius%20Token%2001;pin-value=1234?module-path=/usr/lib64/libsofthsm2.so";
    const INVALID_URL_NO_MODULE_PATH: &str =
        "pkcs11:token=Ostiarius%20Token%2001;pin-value=1234;object=Ostiarius%20Server%20Key%2001";

    #[test]
    pub fn invalid_url_no_object() {
        let url = url::Url::parse(INVALID_URL_NO_OBJECT).unwrap();
        let result = Pkcs11RsaPrivateKey::new(&url);
        assert!(matches!(result, Err(crate::error::Error::InvalidUri(_))));
    }

    #[test]
    pub fn invalid_url_no_module_path() {
        let url = url::Url::parse(INVALID_URL_NO_MODULE_PATH).unwrap();
        let result = Pkcs11RsaPrivateKey::new(&url);
        assert!(matches!(result, Err(crate::error::Error::InvalidUri(_))));
    }
}
