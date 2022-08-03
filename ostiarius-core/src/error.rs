//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use openssl;
use thiserror::Error;
use toml;
use url;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] openssl::error::ErrorStack),
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
}

pub type Result<T> = std::result::Result<T, Error>;
