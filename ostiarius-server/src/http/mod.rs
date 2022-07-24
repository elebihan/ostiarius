//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

mod authorizations;
mod index;

use crate::config::Config;
use crate::models;
use anyhow::Context;
use axum::{extract::Extension, Router};
use ostiarius_core::Checker;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;

#[derive(Clone)]
struct ApiContext {
    checker: Arc<Checker>,
    database: models::Database,
}

pub async fn serve(config: Config, database: models::Database) -> anyhow::Result<()> {
    let addr = SocketAddr::new(config.address, config.port);
    let api_context = ApiContext {
        checker: Arc::new(config.checker),
        database,
    };
    let service = ServiceBuilder::new().layer(Extension(api_context));
    let app = Router::new()
        .merge(index::router())
        .merge(authorizations::router())
        .layer(service);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .context("failed to run HTTP server")
}
