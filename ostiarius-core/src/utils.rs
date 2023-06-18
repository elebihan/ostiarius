//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::{Error, Result};
use percent_encoding::NON_ALPHANUMERIC;

pub fn insert_password(password: &str, url: &str) -> Result<String> {
    let (scheme, components) = url.split_once(':').ok_or(Error::InvalidUri(url.into()))?;
    let password =
        percent_encoding::percent_encode(password.as_bytes(), NON_ALPHANUMERIC).to_string();
    let u = match scheme {
        "file" => {
            let parts = url.split_once('?');
            let head = parts.map(|(h, _)| h).unwrap_or(url);
            [head, "?password=", &password].join("")
        }
        "pkcs11" => {
            let (old_params, module) = components
                .split_once('?')
                .ok_or(Error::InvalidUri(url.into()))?;
            let new_params = old_params
                .split(';')
                .filter(|p| !p.starts_with("pin-value="))
                .flat_map(|p| [p, ";"]);
            let mut fields = vec!["pkcs11:"];
            fields.extend(new_params);
            fields.push("pin-value=");
            fields.push(&password);
            fields.push("?");
            fields.push(module);
            fields.join("")
        }
        _ => return Err(Error::InvalidUri(url.into())),
    };
    Ok(u)
}

pub fn strip_trailing_newline(input: &mut String) -> &mut String {
    let new_len = input
        .char_indices()
        .rev()
        .find(|(_, c)| !matches!(c, '\n' | '\r'))
        .map_or(0, |(i, _)| i + 1);
    if new_len != input.len() {
        input.truncate(new_len);
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_password() {
        let psswd = " <>#%+{}|\\^~[]`;/?:@=&$";
        let url = "pkcs11:token=Ostiarius%20Token%2002?module-path=/usr/lib64/libsofthsm2.so";
        let test = insert_password(psswd, url).unwrap();
        assert_eq!(test, "pkcs11:token=Ostiarius%20Token%2002;pin-value=%20%3C%3E%23%25%2B%7B%7D%7C%5C%5E%7E%5B%5D%60%3B%2F%3F%3A%40%3D%26%24?module-path=/usr/lib64/libsofthsm2.so");
    }

    #[test]
    fn strip_trailing_newline_test() {
        let mut s = "\n".to_string();
        strip_trailing_newline(&mut s);
        assert_eq!(s, "");

        let mut s = "\r\n".to_string();
        strip_trailing_newline(&mut s);
        assert_eq!(s, "");

        let mut s = "\n\rHello, World".to_string();
        strip_trailing_newline(&mut s);
        assert_eq!(s, "\n\rHello, World");

        let mut s = "Hello, World\n".to_string();
        strip_trailing_newline(&mut s);
        assert_eq!(s, "Hello, World");

        let mut s = "Hello, World\r\n".to_string();
        strip_trailing_newline(&mut s);
        assert_eq!(s, "Hello, World");

        let mut s = "Hello, World\n\n\r\n\r\n".to_string();
        strip_trailing_newline(&mut s);
        assert_eq!(s, "Hello, World");

        let mut s = "".to_string();
        strip_trailing_newline(&mut s);
        assert_eq!(s, "");
    }
}
