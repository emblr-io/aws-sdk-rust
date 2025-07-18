// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateServerEngineAttributesOutput {
    /// <p>Contains the response to an <code>UpdateServerEngineAttributes</code> request.</p>
    pub server: ::std::option::Option<crate::types::Server>,
    _request_id: Option<String>,
}
impl UpdateServerEngineAttributesOutput {
    /// <p>Contains the response to an <code>UpdateServerEngineAttributes</code> request.</p>
    pub fn server(&self) -> ::std::option::Option<&crate::types::Server> {
        self.server.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateServerEngineAttributesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateServerEngineAttributesOutput {
    /// Creates a new builder-style object to manufacture [`UpdateServerEngineAttributesOutput`](crate::operation::update_server_engine_attributes::UpdateServerEngineAttributesOutput).
    pub fn builder() -> crate::operation::update_server_engine_attributes::builders::UpdateServerEngineAttributesOutputBuilder {
        crate::operation::update_server_engine_attributes::builders::UpdateServerEngineAttributesOutputBuilder::default()
    }
}

/// A builder for [`UpdateServerEngineAttributesOutput`](crate::operation::update_server_engine_attributes::UpdateServerEngineAttributesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateServerEngineAttributesOutputBuilder {
    pub(crate) server: ::std::option::Option<crate::types::Server>,
    _request_id: Option<String>,
}
impl UpdateServerEngineAttributesOutputBuilder {
    /// <p>Contains the response to an <code>UpdateServerEngineAttributes</code> request.</p>
    pub fn server(mut self, input: crate::types::Server) -> Self {
        self.server = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the response to an <code>UpdateServerEngineAttributes</code> request.</p>
    pub fn set_server(mut self, input: ::std::option::Option<crate::types::Server>) -> Self {
        self.server = input;
        self
    }
    /// <p>Contains the response to an <code>UpdateServerEngineAttributes</code> request.</p>
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
    /// Consumes the builder and constructs a [`UpdateServerEngineAttributesOutput`](crate::operation::update_server_engine_attributes::UpdateServerEngineAttributesOutput).
    pub fn build(self) -> crate::operation::update_server_engine_attributes::UpdateServerEngineAttributesOutput {
        crate::operation::update_server_engine_attributes::UpdateServerEngineAttributesOutput {
            server: self.server,
            _request_id: self._request_id,
        }
    }
}
