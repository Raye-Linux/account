use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use raye_account_common::api::ApiError;

#[derive(Debug)]
pub enum Error {
    BadRequest(&'static str),
    /// OAuth "invalid_grant": a code or refresh token that is wrong, used or expired.
    InvalidGrant,
    Unauthorized,
    Forbidden,
    NotFound,
    TooMany,
    TooLarge,
    Unsupported(&'static str),
    Internal(String),
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::Internal(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Error::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid_request", m),
            Error::InvalidGrant => (StatusCode::BAD_REQUEST, "invalid_grant", "sign in again"),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "sign in again"),
            Error::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "not allowed"),
            Error::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found"),
            Error::TooMany => (StatusCode::TOO_MANY_REQUESTS, "slow_down", "too many requests"),
            Error::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large", "too large"),
            Error::Unsupported(m) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported", m),
            Error::Internal(detail) => {
                // The detail stays in the log; the client gets nothing it could map the database with.
                tracing::error!(%detail, "request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "something went wrong")
            }
        };
        let mut res = (
            status,
            Json(ApiError { error: code.into(), message: message.into() }),
        )
            .into_response();
        if status == StatusCode::UNAUTHORIZED {
            res.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer"),
            );
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            res.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from_static("60"));
        }
        res
    }
}
