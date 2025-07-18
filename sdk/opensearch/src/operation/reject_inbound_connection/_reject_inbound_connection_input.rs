// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the request parameters to the <code>RejectInboundConnection</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RejectInboundConnectionInput {
    /// <p>The unique identifier of the inbound connection to reject.</p>
    pub connection_id: ::std::option::Option<::std::string::String>,
}
impl RejectInboundConnectionInput {
    /// <p>The unique identifier of the inbound connection to reject.</p>
    pub fn connection_id(&self) -> ::std::option::Option<&str> {
        self.connection_id.as_deref()
    }
}
impl RejectInboundConnectionInput {
    /// Creates a new builder-style object to manufacture [`RejectInboundConnectionInput`](crate::operation::reject_inbound_connection::RejectInboundConnectionInput).
    pub fn builder() -> crate::operation::reject_inbound_connection::builders::RejectInboundConnectionInputBuilder {
        crate::operation::reject_inbound_connection::builders::RejectInboundConnectionInputBuilder::default()
    }
}

/// A builder for [`RejectInboundConnectionInput`](crate::operation::reject_inbound_connection::RejectInboundConnectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RejectInboundConnectionInputBuilder {
    pub(crate) connection_id: ::std::option::Option<::std::string::String>,
}
impl RejectInboundConnectionInputBuilder {
    /// <p>The unique identifier of the inbound connection to reject.</p>
    /// This field is required.
    pub fn connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the inbound connection to reject.</p>
    pub fn set_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_id = input;
        self
    }
    /// <p>The unique identifier of the inbound connection to reject.</p>
    pub fn get_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_id
    }
    /// Consumes the builder and constructs a [`RejectInboundConnectionInput`](crate::operation::reject_inbound_connection::RejectInboundConnectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::reject_inbound_connection::RejectInboundConnectionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::reject_inbound_connection::RejectInboundConnectionInput {
            connection_id: self.connection_id,
        })
    }
}
