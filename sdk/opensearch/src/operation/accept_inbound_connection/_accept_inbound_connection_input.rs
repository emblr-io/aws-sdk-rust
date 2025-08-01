// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code>AcceptInboundConnection</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AcceptInboundConnectionInput {
    /// <p>The ID of the inbound connection to accept.</p>
    pub connection_id: ::std::option::Option<::std::string::String>,
}
impl AcceptInboundConnectionInput {
    /// <p>The ID of the inbound connection to accept.</p>
    pub fn connection_id(&self) -> ::std::option::Option<&str> {
        self.connection_id.as_deref()
    }
}
impl AcceptInboundConnectionInput {
    /// Creates a new builder-style object to manufacture [`AcceptInboundConnectionInput`](crate::operation::accept_inbound_connection::AcceptInboundConnectionInput).
    pub fn builder() -> crate::operation::accept_inbound_connection::builders::AcceptInboundConnectionInputBuilder {
        crate::operation::accept_inbound_connection::builders::AcceptInboundConnectionInputBuilder::default()
    }
}

/// A builder for [`AcceptInboundConnectionInput`](crate::operation::accept_inbound_connection::AcceptInboundConnectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AcceptInboundConnectionInputBuilder {
    pub(crate) connection_id: ::std::option::Option<::std::string::String>,
}
impl AcceptInboundConnectionInputBuilder {
    /// <p>The ID of the inbound connection to accept.</p>
    /// This field is required.
    pub fn connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the inbound connection to accept.</p>
    pub fn set_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_id = input;
        self
    }
    /// <p>The ID of the inbound connection to accept.</p>
    pub fn get_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_id
    }
    /// Consumes the builder and constructs a [`AcceptInboundConnectionInput`](crate::operation::accept_inbound_connection::AcceptInboundConnectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::accept_inbound_connection::AcceptInboundConnectionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::accept_inbound_connection::AcceptInboundConnectionInput {
            connection_id: self.connection_id,
        })
    }
}
