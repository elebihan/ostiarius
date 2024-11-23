//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::Error;

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

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_URL_ENCODED_PASSWORD: &str =
        "pkcs11:token=Ostiarius%20Token%2002;object=Ostiarius%20Server%20key%2002;pin-value=%20%3C%3E%23%25%2B%7B%7D%7C%5C%5E%7E%5B%5D%60%3B%2F%3F%3A%40%3D%26%24?module-path=/usr/lib64/libsofthsm2.so";
    const DECODED_PASSWORD: &str = " <>#%+{}|\\^~[]`;/?:@=&$";

    #[test]
    fn try_from_with_password() {
        let url = Url::parse(VALID_URL_ENCODED_PASSWORD).unwrap();
        let pkcs11url = Pkcs11Url::try_from(&url).unwrap();
        assert_eq!(pkcs11url.pin(), DECODED_PASSWORD);
    }
}
