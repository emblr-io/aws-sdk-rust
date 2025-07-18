// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAiGuardrailOutput {
    /// <p>The data of the AI Guardrail.</p>
    pub ai_guardrail: ::std::option::Option<crate::types::AiGuardrailData>,
    /// <p>The version number of the AI Guardrail version (returned if an AI Guardrail version was specified via use of a qualifier for the <code>aiGuardrailId</code> on the request).</p>
    pub version_number: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl GetAiGuardrailOutput {
    /// <p>The data of the AI Guardrail.</p>
    pub fn ai_guardrail(&self) -> ::std::option::Option<&crate::types::AiGuardrailData> {
        self.ai_guardrail.as_ref()
    }
    /// <p>The version number of the AI Guardrail version (returned if an AI Guardrail version was specified via use of a qualifier for the <code>aiGuardrailId</code> on the request).</p>
    pub fn version_number(&self) -> ::std::option::Option<i64> {
        self.version_number
    }
}
impl ::aws_types::request_id::RequestId for GetAiGuardrailOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAiGuardrailOutput {
    /// Creates a new builder-style object to manufacture [`GetAiGuardrailOutput`](crate::operation::get_ai_guardrail::GetAiGuardrailOutput).
    pub fn builder() -> crate::operation::get_ai_guardrail::builders::GetAiGuardrailOutputBuilder {
        crate::operation::get_ai_guardrail::builders::GetAiGuardrailOutputBuilder::default()
    }
}

/// A builder for [`GetAiGuardrailOutput`](crate::operation::get_ai_guardrail::GetAiGuardrailOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAiGuardrailOutputBuilder {
    pub(crate) ai_guardrail: ::std::option::Option<crate::types::AiGuardrailData>,
    pub(crate) version_number: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl GetAiGuardrailOutputBuilder {
    /// <p>The data of the AI Guardrail.</p>
    pub fn ai_guardrail(mut self, input: crate::types::AiGuardrailData) -> Self {
        self.ai_guardrail = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data of the AI Guardrail.</p>
    pub fn set_ai_guardrail(mut self, input: ::std::option::Option<crate::types::AiGuardrailData>) -> Self {
        self.ai_guardrail = input;
        self
    }
    /// <p>The data of the AI Guardrail.</p>
    pub fn get_ai_guardrail(&self) -> &::std::option::Option<crate::types::AiGuardrailData> {
        &self.ai_guardrail
    }
    /// <p>The version number of the AI Guardrail version (returned if an AI Guardrail version was specified via use of a qualifier for the <code>aiGuardrailId</code> on the request).</p>
    pub fn version_number(mut self, input: i64) -> Self {
        self.version_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number of the AI Guardrail version (returned if an AI Guardrail version was specified via use of a qualifier for the <code>aiGuardrailId</code> on the request).</p>
    pub fn set_version_number(mut self, input: ::std::option::Option<i64>) -> Self {
        self.version_number = input;
        self
    }
    /// <p>The version number of the AI Guardrail version (returned if an AI Guardrail version was specified via use of a qualifier for the <code>aiGuardrailId</code> on the request).</p>
    pub fn get_version_number(&self) -> &::std::option::Option<i64> {
        &self.version_number
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAiGuardrailOutput`](crate::operation::get_ai_guardrail::GetAiGuardrailOutput).
    pub fn build(self) -> crate::operation::get_ai_guardrail::GetAiGuardrailOutput {
        crate::operation::get_ai_guardrail::GetAiGuardrailOutput {
            ai_guardrail: self.ai_guardrail,
            version_number: self.version_number,
            _request_id: self._request_id,
        }
    }
}
