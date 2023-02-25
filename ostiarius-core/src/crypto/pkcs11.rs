//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::{crypto::PrivateKey, Error, Result};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectHandle},
    session::{Session, SessionFlags, UserType},
};
use std::collections::HashMap;
use std::str::FromStr;
use url::Url;

#[derive(Debug)]
struct Pkcs11Params(HashMap<String, String>);

impl FromStr for Pkcs11Params {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let items = s.split(';');
        let result: std::result::Result<HashMap<String, String>, Self::Err> = items
            .map(|kv| {
                kv.find('=')
                    .ok_or(Error::InvalidUri("malformed parameter".to_string()))
                    .map(move |p| (kv[0..p].to_string(), kv[p + 1..].replace("%20", " ")))
            })
            .collect();
        Ok(Pkcs11Params(result?))
    }
}

impl TryFrom<&Url> for Pkcs11Params {
    type Error = Error;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        let mut params = url.path().parse::<Pkcs11Params>()?;
        let module_path = url
            .query_pairs()
            .filter_map(|(k, v)| {
                if k == "module-path" {
                    Some(v.to_string())
                } else {
                    None
                }
            })
            .next()
            .ok_or(Error::InvalidUri("missing module-path".to_string()))?;
        params.0.insert("module-path".to_string(), module_path);
        Ok(params)
    }
}

#[derive(Debug, Clone)]
pub struct Pkcs11Url {
    module_path: String,
    token: String,
    pin: String,
    object: String,
}

impl Pkcs11Url {
    pub fn module_path(&self) -> &str {
        &self.module_path
    }

    #[allow(dead_code)]
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn pin(&self) -> &str {
        &self.pin
    }

    pub fn object(&self) -> &str {
        &self.object
    }
}

impl TryFrom<&Url> for Pkcs11Url {
    type Error = Error;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        let mut params = Pkcs11Params::try_from(url)?;
        Ok(Pkcs11Url {
            module_path: params
                .0
                .remove("module-path")
                .ok_or(Error::InvalidUri("missing module-path".to_string()))?,
            token: params
                .0
                .remove("token")
                .ok_or(Error::InvalidUri("missing token".to_string()))?,
            pin: percent_encoding::percent_decode(
                params
                    .0
                    .remove("pin-value")
                    .ok_or(Error::InvalidUri("missing pin-value".to_string()))?
                    .as_bytes(),
            )
            .decode_utf8_lossy()
            .to_string(),
            object: params
                .0
                .remove("object")
                .ok_or(Error::InvalidUri("missing object".to_string()))?,
        })
    }
}

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

    const INVALID_URL_NO_OBJECT: &'static str =
        "pkcs11:token=Ostiarius%20Token%2001;pin-value=1234?module-path=/usr/lib64/libsofthsm2.so";
    const INVALID_URL_NO_MODULE_PATH: &'static str =
        "pkcs11:token=Ostiarius%20Token%2001;pin-value=1234;object=Ostiarius%20Server%20Key%2001";
    const VALID_URL_ENCODED_PASSWD: &'static str =
        "pkcs11:token=Ostiarius%20Token%2002;object=Ostiarius%20Server%20key%2002;pin-value=%20%3C%3E%23%25%2B%7B%7D%7C%5C%5E%7E%5B%5D%60%3B%2F%3F%3A%40%3D%26%24?module-path=/usr/lib64/libsofthsm2.so";

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

    #[test]
    fn pkcs11url_tryfrom_decode_passwd() {
        let url = Url::parse(VALID_URL_ENCODED_PASSWD).unwrap();
        let pkcs11url = Pkcs11Url::try_from(&url).unwrap();
        let expected_decoded_passwd = " <>#%+{}|\\^~[]`;/?:@=&$";
        assert_eq!(pkcs11url.pin(), expected_decoded_passwd);
    }
}
