//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use cryptoki;
use openssl;
use thiserror::Error;
use toml;
use url;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("TOML deserialization error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("URL parsing error: {0}")]
    Url(#[from] url::ParseError),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Invalid path: {0:?}")]
    InvalidPath(std::ffi::OsString),
    #[error("Invalid URI: {0}")]
    InvalidUri(String),
    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

pub type Result<T> = std::result::Result<T, Error>;
