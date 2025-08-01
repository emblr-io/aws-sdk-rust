// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportServerEngineAttributeOutput {
    /// <p>The requested engine attribute pair with attribute name and value.</p>
    pub engine_attribute: ::std::option::Option<crate::types::EngineAttribute>,
    /// <p>The server name used in the request.</p>
    pub server_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ExportServerEngineAttributeOutput {
    /// <p>The requested engine attribute pair with attribute name and value.</p>
    pub fn engine_attribute(&self) -> ::std::option::Option<&crate::types::EngineAttribute> {
        self.engine_attribute.as_ref()
    }
    /// <p>The server name used in the request.</p>
    pub fn server_name(&self) -> ::std::option::Option<&str> {
        self.server_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ExportServerEngineAttributeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ExportServerEngineAttributeOutput {
    /// Creates a new builder-style object to manufacture [`ExportServerEngineAttributeOutput`](crate::operation::export_server_engine_attribute::ExportServerEngineAttributeOutput).
    pub fn builder() -> crate::operation::export_server_engine_attribute::builders::ExportServerEngineAttributeOutputBuilder {
        crate::operation::export_server_engine_attribute::builders::ExportServerEngineAttributeOutputBuilder::default()
    }
}

/// A builder for [`ExportServerEngineAttributeOutput`](crate::operation::export_server_engine_attribute::ExportServerEngineAttributeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportServerEngineAttributeOutputBuilder {
    pub(crate) engine_attribute: ::std::option::Option<crate::types::EngineAttribute>,
    pub(crate) server_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ExportServerEngineAttributeOutputBuilder {
    /// <p>The requested engine attribute pair with attribute name and value.</p>
    pub fn engine_attribute(mut self, input: crate::types::EngineAttribute) -> Self {
        self.engine_attribute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The requested engine attribute pair with attribute name and value.</p>
    pub fn set_engine_attribute(mut self, input: ::std::option::Option<crate::types::EngineAttribute>) -> Self {
        self.engine_attribute = input;
        self
    }
    /// <p>The requested engine attribute pair with attribute name and value.</p>
    pub fn get_engine_attribute(&self) -> &::std::option::Option<crate::types::EngineAttribute> {
        &self.engine_attribute
    }
    /// <p>The server name used in the request.</p>
    pub fn server_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The server name used in the request.</p>
    pub fn set_server_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_name = input;
        self
    }
    /// <p>The server name used in the request.</p>
    pub fn get_server_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ExportServerEngineAttributeOutput`](crate::operation::export_server_engine_attribute::ExportServerEngineAttributeOutput).
    pub fn build(self) -> crate::operation::export_server_engine_attribute::ExportServerEngineAttributeOutput {
        crate::operation::export_server_engine_attribute::ExportServerEngineAttributeOutput {
            engine_attribute: self.engine_attribute,
            server_name: self.server_name,
            _request_id: self._request_id,
        }
    }
}
