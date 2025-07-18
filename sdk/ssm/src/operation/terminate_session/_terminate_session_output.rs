// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TerminateSessionOutput {
    /// <p>The ID of the session that has been terminated.</p>
    pub session_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl TerminateSessionOutput {
    /// <p>The ID of the session that has been terminated.</p>
    pub fn session_id(&self) -> ::std::option::Option<&str> {
        self.session_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for TerminateSessionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl TerminateSessionOutput {
    /// Creates a new builder-style object to manufacture [`TerminateSessionOutput`](crate::operation::terminate_session::TerminateSessionOutput).
    pub fn builder() -> crate::operation::terminate_session::builders::TerminateSessionOutputBuilder {
        crate::operation::terminate_session::builders::TerminateSessionOutputBuilder::default()
    }
}

/// A builder for [`TerminateSessionOutput`](crate::operation::terminate_session::TerminateSessionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TerminateSessionOutputBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl TerminateSessionOutputBuilder {
    /// <p>The ID of the session that has been terminated.</p>
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the session that has been terminated.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The ID of the session that has been terminated.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`TerminateSessionOutput`](crate::operation::terminate_session::TerminateSessionOutput).
    pub fn build(self) -> crate::operation::terminate_session::TerminateSessionOutput {
        crate::operation::terminate_session::TerminateSessionOutput {
            session_id: self.session_id,
            _request_id: self._request_id,
        }
    }
}
