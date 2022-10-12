//
// Copyright (C) 2022 Eric Le Bihan <eric.le.bihan.dev@free.fr>
//
// SPDX-License-Identifier: MIT
//

use crate::http::ApiContext;
use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use ostiarius_core::{Authorization, Error, Request};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize, Default)]
struct Pagination {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

async fn authorizations_index(
    pagination: Option<Query<Pagination>>,
    Extension(ctx): Extension<ApiContext>,
) -> impl IntoResponse {
    let authorizations = ctx.database.lock().await;
    let Query(pagination) = pagination.unwrap_or_default();
    let authorizations = authorizations
        .values()
        .skip(pagination.offset.unwrap_or(0))
        .take(pagination.limit.unwrap_or(usize::MAX))
        .cloned()
        .collect::<Vec<_>>();
    Json(authorizations)
}

async fn authorizations_get(
    Path(id): Path<Uuid>,
    Extension(ctx): Extension<ApiContext>,
) -> std::result::Result<Json<Authorization>, StatusCode> {
    let authorizations = ctx.database.lock().await;
    let authorization = authorizations.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(authorization.clone()))
}

async fn authorizations_create(
    Json(request): Json<Request>,
    Extension(ctx): Extension<ApiContext>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    let authorization = match ctx.checker.check(&request) {
        Err(ref e) if matches!(e, Error::Unauthorized) => return Err(StatusCode::FORBIDDEN),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Ok(a) => a,
    };
    let id = authorization.id;
    let mut authorizations = ctx.database.lock().await;
    authorizations.insert(authorization.id, authorization);
    Ok((StatusCode::CREATED, Json(id)))
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/api/v1/authorizations",
            get(authorizations_index).post(authorizations_create),
        )
        .route("/api/v1/authorizations/:id", get(authorizations_get))
}
