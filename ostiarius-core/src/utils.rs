//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::{Error, Result};

pub fn insert_password(password: &str, url: &str) -> Result<String> {
    let (scheme, components) = url.split_once(":").ok_or(Error::InvalidUri(url.into()))?;
    let u = match scheme {
        "file" => {
            let parts = url.split_once("?");
            let head = parts.map(|(h, _)| h).unwrap_or(url);
            [head, "?password=", password].join("")
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
            fields.push(password);
            fields.push("?");
            fields.push(module);
            fields.join("")
        }
        _ => return Err(Error::InvalidUri(url.into())),
    };
    Ok(String::from(u))
}
