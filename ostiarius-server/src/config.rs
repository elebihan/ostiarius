//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use ostiarius_core::Checker;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub address: IpAddr,
    pub port: u16,
    pub checker: Checker,
}
