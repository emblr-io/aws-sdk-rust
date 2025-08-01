// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a <code>CreateOutboundConnection</code> request. Contains details about the newly created cross-cluster connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateOutboundConnectionOutput {
    /// <p>Information about the source (local) domain.</p>
    pub local_domain_info: ::std::option::Option<crate::types::DomainInformationContainer>,
    /// <p>Information about the destination (remote) domain.</p>
    pub remote_domain_info: ::std::option::Option<crate::types::DomainInformationContainer>,
    /// <p>Name of the connection.</p>
    pub connection_alias: ::std::option::Option<::std::string::String>,
    /// <p>The status of the connection.</p>
    pub connection_status: ::std::option::Option<crate::types::OutboundConnectionStatus>,
    /// <p>The unique identifier for the created outbound connection, which is used for subsequent operations on the connection.</p>
    pub connection_id: ::std::option::Option<::std::string::String>,
    /// <p>The connection mode.</p>
    pub connection_mode: ::std::option::Option<crate::types::ConnectionMode>,
    /// <p>The <code>ConnectionProperties</code> for the newly created connection.</p>
    pub connection_properties: ::std::option::Option<crate::types::ConnectionProperties>,
    _request_id: Option<String>,
}
impl CreateOutboundConnectionOutput {
    /// <p>Information about the source (local) domain.</p>
    pub fn local_domain_info(&self) -> ::std::option::Option<&crate::types::DomainInformationContainer> {
        self.local_domain_info.as_ref()
    }
    /// <p>Information about the destination (remote) domain.</p>
    pub fn remote_domain_info(&self) -> ::std::option::Option<&crate::types::DomainInformationContainer> {
        self.remote_domain_info.as_ref()
    }
    /// <p>Name of the connection.</p>
    pub fn connection_alias(&self) -> ::std::option::Option<&str> {
        self.connection_alias.as_deref()
    }
    /// <p>The status of the connection.</p>
    pub fn connection_status(&self) -> ::std::option::Option<&crate::types::OutboundConnectionStatus> {
        self.connection_status.as_ref()
    }
    /// <p>The unique identifier for the created outbound connection, which is used for subsequent operations on the connection.</p>
    pub fn connection_id(&self) -> ::std::option::Option<&str> {
        self.connection_id.as_deref()
    }
    /// <p>The connection mode.</p>
    pub fn connection_mode(&self) -> ::std::option::Option<&crate::types::ConnectionMode> {
        self.connection_mode.as_ref()
    }
    /// <p>The <code>ConnectionProperties</code> for the newly created connection.</p>
    pub fn connection_properties(&self) -> ::std::option::Option<&crate::types::ConnectionProperties> {
        self.connection_properties.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateOutboundConnectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateOutboundConnectionOutput {
    /// Creates a new builder-style object to manufacture [`CreateOutboundConnectionOutput`](crate::operation::create_outbound_connection::CreateOutboundConnectionOutput).
    pub fn builder() -> crate::operation::create_outbound_connection::builders::CreateOutboundConnectionOutputBuilder {
        crate::operation::create_outbound_connection::builders::CreateOutboundConnectionOutputBuilder::default()
    }
}

/// A builder for [`CreateOutboundConnectionOutput`](crate::operation::create_outbound_connection::CreateOutboundConnectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateOutboundConnectionOutputBuilder {
    pub(crate) local_domain_info: ::std::option::Option<crate::types::DomainInformationContainer>,
    pub(crate) remote_domain_info: ::std::option::Option<crate::types::DomainInformationContainer>,
    pub(crate) connection_alias: ::std::option::Option<::std::string::String>,
    pub(crate) connection_status: ::std::option::Option<crate::types::OutboundConnectionStatus>,
    pub(crate) connection_id: ::std::option::Option<::std::string::String>,
    pub(crate) connection_mode: ::std::option::Option<crate::types::ConnectionMode>,
    pub(crate) connection_properties: ::std::option::Option<crate::types::ConnectionProperties>,
    _request_id: Option<String>,
}
impl CreateOutboundConnectionOutputBuilder {
    /// <p>Information about the source (local) domain.</p>
    pub fn local_domain_info(mut self, input: crate::types::DomainInformationContainer) -> Self {
        self.local_domain_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the source (local) domain.</p>
    pub fn set_local_domain_info(mut self, input: ::std::option::Option<crate::types::DomainInformationContainer>) -> Self {
        self.local_domain_info = input;
        self
    }
    /// <p>Information about the source (local) domain.</p>
    pub fn get_local_domain_info(&self) -> &::std::option::Option<crate::types::DomainInformationContainer> {
        &self.local_domain_info
    }
    /// <p>Information about the destination (remote) domain.</p>
    pub fn remote_domain_info(mut self, input: crate::types::DomainInformationContainer) -> Self {
        self.remote_domain_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the destination (remote) domain.</p>
    pub fn set_remote_domain_info(mut self, input: ::std::option::Option<crate::types::DomainInformationContainer>) -> Self {
        self.remote_domain_info = input;
        self
    }
    /// <p>Information about the destination (remote) domain.</p>
    pub fn get_remote_domain_info(&self) -> &::std::option::Option<crate::types::DomainInformationContainer> {
        &self.remote_domain_info
    }
    /// <p>Name of the connection.</p>
    pub fn connection_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the connection.</p>
    pub fn set_connection_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_alias = input;
        self
    }
    /// <p>Name of the connection.</p>
    pub fn get_connection_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_alias
    }
    /// <p>The status of the connection.</p>
    pub fn connection_status(mut self, input: crate::types::OutboundConnectionStatus) -> Self {
        self.connection_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the connection.</p>
    pub fn set_connection_status(mut self, input: ::std::option::Option<crate::types::OutboundConnectionStatus>) -> Self {
        self.connection_status = input;
        self
    }
    /// <p>The status of the connection.</p>
    pub fn get_connection_status(&self) -> &::std::option::Option<crate::types::OutboundConnectionStatus> {
        &self.connection_status
    }
    /// <p>The unique identifier for the created outbound connection, which is used for subsequent operations on the connection.</p>
    pub fn connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the created outbound connection, which is used for subsequent operations on the connection.</p>
    pub fn set_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_id = input;
        self
    }
    /// <p>The unique identifier for the created outbound connection, which is used for subsequent operations on the connection.</p>
    pub fn get_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_id
    }
    /// <p>The connection mode.</p>
    pub fn connection_mode(mut self, input: crate::types::ConnectionMode) -> Self {
        self.connection_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The connection mode.</p>
    pub fn set_connection_mode(mut self, input: ::std::option::Option<crate::types::ConnectionMode>) -> Self {
        self.connection_mode = input;
        self
    }
    /// <p>The connection mode.</p>
    pub fn get_connection_mode(&self) -> &::std::option::Option<crate::types::ConnectionMode> {
        &self.connection_mode
    }
    /// <p>The <code>ConnectionProperties</code> for the newly created connection.</p>
    pub fn connection_properties(mut self, input: crate::types::ConnectionProperties) -> Self {
        self.connection_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>ConnectionProperties</code> for the newly created connection.</p>
    pub fn set_connection_properties(mut self, input: ::std::option::Option<crate::types::ConnectionProperties>) -> Self {
        self.connection_properties = input;
        self
    }
    /// <p>The <code>ConnectionProperties</code> for the newly created connection.</p>
    pub fn get_connection_properties(&self) -> &::std::option::Option<crate::types::ConnectionProperties> {
        &self.connection_properties
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateOutboundConnectionOutput`](crate::operation::create_outbound_connection::CreateOutboundConnectionOutput).
    pub fn build(self) -> crate::operation::create_outbound_connection::CreateOutboundConnectionOutput {
        crate::operation::create_outbound_connection::CreateOutboundConnectionOutput {
            local_domain_info: self.local_domain_info,
            remote_domain_info: self.remote_domain_info,
            connection_alias: self.connection_alias,
            connection_status: self.connection_status,
            connection_id: self.connection_id,
            connection_mode: self.connection_mode,
            connection_properties: self.connection_properties,
            _request_id: self._request_id,
        }
    }
}
