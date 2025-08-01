// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteConnectorOutput {
    /// <p>The Amazon Resource Name (ARN) of the connector that you requested to delete.</p>
    pub connector_arn: ::std::option::Option<::std::string::String>,
    /// <p>The state of the connector that you requested to delete.</p>
    pub connector_state: ::std::option::Option<crate::types::ConnectorState>,
    _request_id: Option<String>,
}
impl DeleteConnectorOutput {
    /// <p>The Amazon Resource Name (ARN) of the connector that you requested to delete.</p>
    pub fn connector_arn(&self) -> ::std::option::Option<&str> {
        self.connector_arn.as_deref()
    }
    /// <p>The state of the connector that you requested to delete.</p>
    pub fn connector_state(&self) -> ::std::option::Option<&crate::types::ConnectorState> {
        self.connector_state.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteConnectorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteConnectorOutput {
    /// Creates a new builder-style object to manufacture [`DeleteConnectorOutput`](crate::operation::delete_connector::DeleteConnectorOutput).
    pub fn builder() -> crate::operation::delete_connector::builders::DeleteConnectorOutputBuilder {
        crate::operation::delete_connector::builders::DeleteConnectorOutputBuilder::default()
    }
}

/// A builder for [`DeleteConnectorOutput`](crate::operation::delete_connector::DeleteConnectorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteConnectorOutputBuilder {
    pub(crate) connector_arn: ::std::option::Option<::std::string::String>,
    pub(crate) connector_state: ::std::option::Option<crate::types::ConnectorState>,
    _request_id: Option<String>,
}
impl DeleteConnectorOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the connector that you requested to delete.</p>
    pub fn connector_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connector_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the connector that you requested to delete.</p>
    pub fn set_connector_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connector_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the connector that you requested to delete.</p>
    pub fn get_connector_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.connector_arn
    }
    /// <p>The state of the connector that you requested to delete.</p>
    pub fn connector_state(mut self, input: crate::types::ConnectorState) -> Self {
        self.connector_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the connector that you requested to delete.</p>
    pub fn set_connector_state(mut self, input: ::std::option::Option<crate::types::ConnectorState>) -> Self {
        self.connector_state = input;
        self
    }
    /// <p>The state of the connector that you requested to delete.</p>
    pub fn get_connector_state(&self) -> &::std::option::Option<crate::types::ConnectorState> {
        &self.connector_state
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteConnectorOutput`](crate::operation::delete_connector::DeleteConnectorOutput).
    pub fn build(self) -> crate::operation::delete_connector::DeleteConnectorOutput {
        crate::operation::delete_connector::DeleteConnectorOutput {
            connector_arn: self.connector_arn,
            connector_state: self.connector_state,
            _request_id: self._request_id,
        }
    }
}
