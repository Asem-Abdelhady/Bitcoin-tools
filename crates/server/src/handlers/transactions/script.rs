//! HTTP surface for script analysis.
//!
//! Transport only: parse the request, call the service, shape the response,
//! map domain errors onto status codes. The analysis itself lives in
//! [`crate::services::transactions::script`].

use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::ApiRejection;
use crate::services::input::InputError;
use crate::services::transactions::script::{AnalyzeScriptRequest, analyze_hex};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::transactions::script::{
    Category, DecodeError, ScriptAnalysis, ScriptFields,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeScriptResponse {
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

impl From<ScriptAnalysis> for AnalyzeScriptResponse {
    fn from(a: ScriptAnalysis) -> Self {
        AnalyzeScriptResponse {
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
                    data: i.data.as_deref().map(hex::encode),
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
pub async fn post_analyze_script(
    payload: Result<Json<AnalyzeScriptRequest>, JsonRejection>,
) -> Result<Json<AnalyzeScriptResponse>, ApiRejection<InputError>> {
    let Json(req) = payload?;
    let analysis = analyze_hex(&req.script).map_err(ApiRejection::Domain)?;
    Ok(Json(analysis.into()))
}
