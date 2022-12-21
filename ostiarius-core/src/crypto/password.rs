//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::{Error, Result};
use rpassword;
use std::path::PathBuf;
#[cfg(unix)]
use std::{io::Read, os::unix::prelude::FromRawFd};

pub enum PasswordProvider {
    Env(String),
    #[cfg(unix)]
    Fd(u8),
    File(PathBuf),
    #[cfg(feature = "visible_password")]
    Pass(String),
    Prompt,
}

impl std::str::FromStr for PasswordProvider {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let fields: Vec<&str> = s.split(':').collect();
        if fields.len() != 2 {
            return Err(Error::InvalidProvider(s.to_string()));
        }
        let provider = match fields[0] {
            #[cfg(unix)]
            "fd" => {
                let fd = fields[1].parse::<u8>()?;
                PasswordProvider::Fd(fd)
            }
            "file" => {
                let path = PathBuf::from(fields[1]);
                PasswordProvider::File(path)
            }
            "env" => PasswordProvider::Env(fields[1].to_string()),
            #[cfg(feature = "visible_password")]
            "pass" => PasswordProvider::Pass(fields[1].to_string()),
            _ => PasswordProvider::Prompt,
        };
        Ok(provider)
    }
}

impl PasswordProvider {
    pub fn provide(&self) -> Result<String> {
        let password = match self {
            PasswordProvider::Env(var) => std::env::var(var)?,
            #[cfg(unix)]
            PasswordProvider::Fd(fd) => {
                let mut file = unsafe { std::fs::File::from_raw_fd(*fd as i32) };
                let mut password = String::new();
                file.read_to_string(&mut password)?;
                password
            }
            PasswordProvider::File(path) => std::fs::read_to_string(path)?,
            #[cfg(feature = "visible_password")]
            PasswordProvider::Pass(value) => value.to_string(),
            PasswordProvider::Prompt => rpassword::prompt_password("Please enter password: ")?,
        };
        Ok(password)
    }
}
