// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a terminated Client VPN endpoint client connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TerminateConnectionStatus {
    /// <p>The ID of the client connection.</p>
    pub connection_id: ::std::option::Option<::std::string::String>,
    /// <p>The state of the client connection.</p>
    pub previous_status: ::std::option::Option<crate::types::ClientVpnConnectionStatus>,
    /// <p>A message about the status of the client connection, if applicable.</p>
    pub current_status: ::std::option::Option<crate::types::ClientVpnConnectionStatus>,
}
impl TerminateConnectionStatus {
    /// <p>The ID of the client connection.</p>
    pub fn connection_id(&self) -> ::std::option::Option<&str> {
        self.connection_id.as_deref()
    }
    /// <p>The state of the client connection.</p>
    pub fn previous_status(&self) -> ::std::option::Option<&crate::types::ClientVpnConnectionStatus> {
        self.previous_status.as_ref()
    }
    /// <p>A message about the status of the client connection, if applicable.</p>
    pub fn current_status(&self) -> ::std::option::Option<&crate::types::ClientVpnConnectionStatus> {
        self.current_status.as_ref()
    }
}
impl TerminateConnectionStatus {
    /// Creates a new builder-style object to manufacture [`TerminateConnectionStatus`](crate::types::TerminateConnectionStatus).
    pub fn builder() -> crate::types::builders::TerminateConnectionStatusBuilder {
        crate::types::builders::TerminateConnectionStatusBuilder::default()
    }
}

/// A builder for [`TerminateConnectionStatus`](crate::types::TerminateConnectionStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TerminateConnectionStatusBuilder {
    pub(crate) connection_id: ::std::option::Option<::std::string::String>,
    pub(crate) previous_status: ::std::option::Option<crate::types::ClientVpnConnectionStatus>,
    pub(crate) current_status: ::std::option::Option<crate::types::ClientVpnConnectionStatus>,
}
impl TerminateConnectionStatusBuilder {
    /// <p>The ID of the client connection.</p>
    pub fn connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the client connection.</p>
    pub fn set_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_id = input;
        self
    }
    /// <p>The ID of the client connection.</p>
    pub fn get_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_id
    }
    /// <p>The state of the client connection.</p>
    pub fn previous_status(mut self, input: crate::types::ClientVpnConnectionStatus) -> Self {
        self.previous_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the client connection.</p>
    pub fn set_previous_status(mut self, input: ::std::option::Option<crate::types::ClientVpnConnectionStatus>) -> Self {
        self.previous_status = input;
        self
    }
    /// <p>The state of the client connection.</p>
    pub fn get_previous_status(&self) -> &::std::option::Option<crate::types::ClientVpnConnectionStatus> {
        &self.previous_status
    }
    /// <p>A message about the status of the client connection, if applicable.</p>
    pub fn current_status(mut self, input: crate::types::ClientVpnConnectionStatus) -> Self {
        self.current_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>A message about the status of the client connection, if applicable.</p>
    pub fn set_current_status(mut self, input: ::std::option::Option<crate::types::ClientVpnConnectionStatus>) -> Self {
        self.current_status = input;
        self
    }
    /// <p>A message about the status of the client connection, if applicable.</p>
    pub fn get_current_status(&self) -> &::std::option::Option<crate::types::ClientVpnConnectionStatus> {
        &self.current_status
    }
    /// Consumes the builder and constructs a [`TerminateConnectionStatus`](crate::types::TerminateConnectionStatus).
    pub fn build(self) -> crate::types::TerminateConnectionStatus {
        crate::types::TerminateConnectionStatus {
            connection_id: self.connection_id,
            previous_status: self.previous_status,
            current_status: self.current_status,
        }
    }
}
