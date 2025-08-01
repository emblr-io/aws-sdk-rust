// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The state of a connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConnectionState {
    /// <p>The connection status of the tunnel. Valid values are <code>CONNECTED</code> and <code>DISCONNECTED</code>.</p>
    pub status: ::std::option::Option<crate::types::ConnectionStatus>,
    /// <p>The last time the connection status was updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ConnectionState {
    /// <p>The connection status of the tunnel. Valid values are <code>CONNECTED</code> and <code>DISCONNECTED</code>.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ConnectionStatus> {
        self.status.as_ref()
    }
    /// <p>The last time the connection status was updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
}
impl ConnectionState {
    /// Creates a new builder-style object to manufacture [`ConnectionState`](crate::types::ConnectionState).
    pub fn builder() -> crate::types::builders::ConnectionStateBuilder {
        crate::types::builders::ConnectionStateBuilder::default()
    }
}

/// A builder for [`ConnectionState`](crate::types::ConnectionState).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConnectionStateBuilder {
    pub(crate) status: ::std::option::Option<crate::types::ConnectionStatus>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ConnectionStateBuilder {
    /// <p>The connection status of the tunnel. Valid values are <code>CONNECTED</code> and <code>DISCONNECTED</code>.</p>
    pub fn status(mut self, input: crate::types::ConnectionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The connection status of the tunnel. Valid values are <code>CONNECTED</code> and <code>DISCONNECTED</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ConnectionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The connection status of the tunnel. Valid values are <code>CONNECTED</code> and <code>DISCONNECTED</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ConnectionStatus> {
        &self.status
    }
    /// <p>The last time the connection status was updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time the connection status was updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The last time the connection status was updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// Consumes the builder and constructs a [`ConnectionState`](crate::types::ConnectionState).
    pub fn build(self) -> crate::types::ConnectionState {
        crate::types::ConnectionState {
            status: self.status,
            last_updated_at: self.last_updated_at,
        }
    }
}
