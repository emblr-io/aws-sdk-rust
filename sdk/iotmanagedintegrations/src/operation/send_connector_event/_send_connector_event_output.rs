// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SendConnectorEventOutput {
    /// <p>The id of the connector between the third-party cloud provider and IoT managed integrations.</p>
    pub connector_id: ::std::string::String,
    _request_id: Option<String>,
}
impl SendConnectorEventOutput {
    /// <p>The id of the connector between the third-party cloud provider and IoT managed integrations.</p>
    pub fn connector_id(&self) -> &str {
        use std::ops::Deref;
        self.connector_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for SendConnectorEventOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SendConnectorEventOutput {
    /// Creates a new builder-style object to manufacture [`SendConnectorEventOutput`](crate::operation::send_connector_event::SendConnectorEventOutput).
    pub fn builder() -> crate::operation::send_connector_event::builders::SendConnectorEventOutputBuilder {
        crate::operation::send_connector_event::builders::SendConnectorEventOutputBuilder::default()
    }
}

/// A builder for [`SendConnectorEventOutput`](crate::operation::send_connector_event::SendConnectorEventOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SendConnectorEventOutputBuilder {
    pub(crate) connector_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SendConnectorEventOutputBuilder {
    /// <p>The id of the connector between the third-party cloud provider and IoT managed integrations.</p>
    /// This field is required.
    pub fn connector_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connector_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The id of the connector between the third-party cloud provider and IoT managed integrations.</p>
    pub fn set_connector_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connector_id = input;
        self
    }
    /// <p>The id of the connector between the third-party cloud provider and IoT managed integrations.</p>
    pub fn get_connector_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connector_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SendConnectorEventOutput`](crate::operation::send_connector_event::SendConnectorEventOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`connector_id`](crate::operation::send_connector_event::builders::SendConnectorEventOutputBuilder::connector_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::send_connector_event::SendConnectorEventOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::send_connector_event::SendConnectorEventOutput {
            connector_id: self.connector_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "connector_id",
                    "connector_id was not specified but it is required when building SendConnectorEventOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
