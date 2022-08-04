//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use axum::{response::Html, routing::get, Router};

async fn index() -> Html<String> {
    Html(format!(
        "<h1>Ostricius Server - {}</h1>",
        env!("CARGO_PKG_VERSION")
    ))
}

pub fn router() -> Router {
    Router::new().route("/", get(index))
}
