//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::{Error, Result};
use percent_encoding::NON_ALPHANUMERIC;

pub fn insert_password(password: &str, url: &str) -> Result<String> {
    let (scheme, components) = url.split_once(":").ok_or(Error::InvalidUri(url.into()))?;
    let psww_slice = password.as_bytes();
    let pass_encode = percent_encoding::percent_encode(psww_slice, NON_ALPHANUMERIC).to_string();
    let u = match scheme {
        "file" => {
            let parts = url.split_once("?");
            let head = parts.map(|(h, _)| h).unwrap_or(url);
            [head, "?password=", &pass_encode].join("")
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
            fields.push(&pass_encode);
            fields.push("?");
            fields.push(module);
            fields.join("")
        }
        _ => return Err(Error::InvalidUri(url.into())),
    };
    Ok(String::from(u))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_password() {
        let psswd = " <>#%+{}|\\^~[]`;/?:@=&$";
        let url = "pkcs11:token=RepairOS EOLE key;object=RepairOS EOLE key?module-path=/usr/lib/libeTPkcs11.so";
        let test = insert_password(psswd, url).unwrap();
        assert_eq!(test, "pkcs11:token=RepairOS EOLE key;object=RepairOS EOLE key;pin-value=%20%3C%3E%23%25%2B%7B%7D%7C%5C%5E%7E%5B%5D%60%3B%2F%3F%3A%40%3D%26%24?module-path=/usr/lib/libeTPkcs11.so");
    }
}