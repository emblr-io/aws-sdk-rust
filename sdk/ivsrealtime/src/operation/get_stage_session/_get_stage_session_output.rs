// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetStageSessionOutput {
    /// <p>The stage session that is returned.</p>
    pub stage_session: ::std::option::Option<crate::types::StageSession>,
    _request_id: Option<String>,
}
impl GetStageSessionOutput {
    /// <p>The stage session that is returned.</p>
    pub fn stage_session(&self) -> ::std::option::Option<&crate::types::StageSession> {
        self.stage_session.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetStageSessionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetStageSessionOutput {
    /// Creates a new builder-style object to manufacture [`GetStageSessionOutput`](crate::operation::get_stage_session::GetStageSessionOutput).
    pub fn builder() -> crate::operation::get_stage_session::builders::GetStageSessionOutputBuilder {
        crate::operation::get_stage_session::builders::GetStageSessionOutputBuilder::default()
    }
}

/// A builder for [`GetStageSessionOutput`](crate::operation::get_stage_session::GetStageSessionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetStageSessionOutputBuilder {
    pub(crate) stage_session: ::std::option::Option<crate::types::StageSession>,
    _request_id: Option<String>,
}
impl GetStageSessionOutputBuilder {
    /// <p>The stage session that is returned.</p>
    pub fn stage_session(mut self, input: crate::types::StageSession) -> Self {
        self.stage_session = ::std::option::Option::Some(input);
        self
    }
    /// <p>The stage session that is returned.</p>
    pub fn set_stage_session(mut self, input: ::std::option::Option<crate::types::StageSession>) -> Self {
        self.stage_session = input;
        self
    }
    /// <p>The stage session that is returned.</p>
    pub fn get_stage_session(&self) -> &::std::option::Option<crate::types::StageSession> {
        &self.stage_session
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetStageSessionOutput`](crate::operation::get_stage_session::GetStageSessionOutput).
    pub fn build(self) -> crate::operation::get_stage_session::GetStageSessionOutput {
        crate::operation::get_stage_session::GetStageSessionOutput {
            stage_session: self.stage_session,
            _request_id: self._request_id,
        }
    }
}
