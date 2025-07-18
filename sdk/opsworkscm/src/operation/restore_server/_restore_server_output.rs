// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RestoreServerOutput {
    /// <p>Describes a configuration management server.</p>
    pub server: ::std::option::Option<crate::types::Server>,
    _request_id: Option<String>,
}
impl RestoreServerOutput {
    /// <p>Describes a configuration management server.</p>
    pub fn server(&self) -> ::std::option::Option<&crate::types::Server> {
        self.server.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for RestoreServerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RestoreServerOutput {
    /// Creates a new builder-style object to manufacture [`RestoreServerOutput`](crate::operation::restore_server::RestoreServerOutput).
    pub fn builder() -> crate::operation::restore_server::builders::RestoreServerOutputBuilder {
        crate::operation::restore_server::builders::RestoreServerOutputBuilder::default()
    }
}

/// A builder for [`RestoreServerOutput`](crate::operation::restore_server::RestoreServerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RestoreServerOutputBuilder {
    pub(crate) server: ::std::option::Option<crate::types::Server>,
    _request_id: Option<String>,
}
impl RestoreServerOutputBuilder {
    /// <p>Describes a configuration management server.</p>
    pub fn server(mut self, input: crate::types::Server) -> Self {
        self.server = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes a configuration management server.</p>
    pub fn set_server(mut self, input: ::std::option::Option<crate::types::Server>) -> Self {
        self.server = input;
        self
    }
    /// <p>Describes a configuration management server.</p>
    pub fn get_server(&self) -> &::std::option::Option<crate::types::Server> {
        &self.server
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RestoreServerOutput`](crate::operation::restore_server::RestoreServerOutput).
    pub fn build(self) -> crate::operation::restore_server::RestoreServerOutput {
        crate::operation::restore_server::RestoreServerOutput {
            server: self.server,
            _request_id: self._request_id,
        }
    }
}
