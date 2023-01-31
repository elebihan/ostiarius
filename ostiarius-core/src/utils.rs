//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::{Error, Result};
use percent_encoding::{percent_decode_str, percent_encode, NON_ALPHANUMERIC};

pub fn insert_password(password: &str, url: &str) -> Result<String> {
    let (scheme, components) = url.split_once(":").ok_or(Error::InvalidUri(url.into()))?;
    let escaped_password = percent_encode(password.as_bytes(), NON_ALPHANUMERIC).to_string();
    let u = match scheme {
        "file" => {
            let parts = url.split_once("?");
            let head = parts.map(|(h, _)| h).unwrap_or(url);
            [head, "?password=", &escaped_password].join("")
        }
        "pkcs11" => {
            let (old_params, module) = components
                .split_once("?")
                .ok_or(Error::InvalidUri(url.into()))?;
            let new_params = old_params
                .split(";")
                .filter(|p| !p.starts_with("pin-value="))
                .flat_map(|p| [p, ";"]);
            let mut fields = vec!["pkcs11:"];
            fields.extend(new_params);
            fields.push("pin-value=");
            fields.push(&escaped_password);
            fields.push("?");
            fields.push(module);
            fields.join("")
        }
        _ => return Err(Error::InvalidUri(url.into())),
    };
    Ok(String::from(u))
}

pub fn unescape_password(password: &str) -> Result<String> {
    let unescaped_password = percent_decode_str(&password).decode_utf8()?;
    Ok(unescaped_password.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert() {
        let res = insert_password("12?34", "file:///foo/bar");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "file:///foo/bar?password=12%3F34");
    }

    #[test]
    fn unescape() {
        let res = unescape_password("12%3F34");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "12?34");
    }
}
