//! HTTP surface for script splitting.
//!
//! Transport only: parse the request, call the service, shape the response,
//! map domain errors onto status codes. The analysis itself lives in
//! [`crate::services::transactions::script`].

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, extract::rejection::JsonRejection};
use serde::{Deserialize, Serialize};

use crate::services::transactions::script::{ScriptServiceError, analyze_hex};
use crate::types::transactions::script::{
    Category, DecodeError, ScriptAnalysis, ScriptFields, to_hex,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitScriptRequest {
    /// The script, hex-encoded, exactly as it appears in a raw transaction.
    pub script: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitScriptResponse {
    pub hex: String,
    pub size_bytes: usize,
    pub kind: String,
    pub asm: String,
    pub fields: ScriptFields,
    pub has_disabled_opcode: bool,
    pub instructions: Vec<InstructionView>,
    /// Present only when the script is malformed. The instructions above are
    /// everything that decoded before the problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DecodeError>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstructionView {
    pub offset: usize,
    pub hex: String,
    pub opcode: String,
    pub category: Category,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_size: Option<usize>,
}

impl From<ScriptAnalysis> for SplitScriptResponse {
    fn from(a: ScriptAnalysis) -> Self {
        SplitScriptResponse {
            hex: a.hex,
            size_bytes: a.size_bytes,
            kind: a.kind.to_string(),
            asm: a.asm,
            fields: a.fields,
            has_disabled_opcode: a.has_disabled_opcode,
            instructions: a
                .instructions
                .into_iter()
                .map(|i| InstructionView {
                    offset: i.offset,
                    hex: format!("{:02x}", i.opcode.to_u8()),
                    opcode: i.opcode.to_string(),
                    category: i.opcode.category(),
                    description: i.opcode.describe(),
                    data_size: i.data.as_ref().map(Vec::len),
                    data: i.data.as_deref().map(to_hex),
                })
                .collect(),
            error: a.error,
        }
    }
}

/// `POST /transactions/script`
///
/// A malformed *script* is still a 200: reporting where it broke is the
/// point of the tool. Only a malformed *request* is a 4xx.
pub async fn post_split_script(
    payload: Result<Json<SplitScriptRequest>, JsonRejection>,
) -> Result<Json<SplitScriptResponse>, SplitScriptError> {
    let Json(req) = payload?;
    let analysis = analyze_hex(&req.script)?;
    Ok(Json(analysis.into()))
}

#[derive(Debug)]
pub enum SplitScriptError {
    BadRequest(String),
    Service(ScriptServiceError),
}

impl From<JsonRejection> for SplitScriptError {
    fn from(r: JsonRejection) -> Self {
        SplitScriptError::BadRequest(r.body_text())
    }
}

impl From<ScriptServiceError> for SplitScriptError {
    fn from(e: ScriptServiceError) -> Self {
        SplitScriptError::Service(e)
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for SplitScriptError {
    fn into_response(self) -> Response {
        let (status, error, message) = match self {
            SplitScriptError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad-request", m),
            SplitScriptError::Service(e) => {
                let (status, slug) = match e {
                    ScriptServiceError::Empty => (StatusCode::BAD_REQUEST, "empty-script"),
                    ScriptServiceError::InvalidHex(_) => (StatusCode::BAD_REQUEST, "invalid-hex"),
                    ScriptServiceError::TooLong { .. } => {
                        (StatusCode::PAYLOAD_TOO_LARGE, "script-too-long")
                    }
                };
                (status, slug, e.to_string())
            }
        };
        (status, Json(ErrorBody { error, message })).into_response()
    }
}
