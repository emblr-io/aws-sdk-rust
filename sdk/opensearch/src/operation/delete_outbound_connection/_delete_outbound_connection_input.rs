// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code>DeleteOutboundConnection</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteOutboundConnectionInput {
    /// <p>The ID of the outbound connection you want to permanently delete.</p>
    pub connection_id: ::std::option::Option<::std::string::String>,
}
impl DeleteOutboundConnectionInput {
    /// <p>The ID of the outbound connection you want to permanently delete.</p>
    pub fn connection_id(&self) -> ::std::option::Option<&str> {
        self.connection_id.as_deref()
    }
}
impl DeleteOutboundConnectionInput {
    /// Creates a new builder-style object to manufacture [`DeleteOutboundConnectionInput`](crate::operation::delete_outbound_connection::DeleteOutboundConnectionInput).
    pub fn builder() -> crate::operation::delete_outbound_connection::builders::DeleteOutboundConnectionInputBuilder {
        crate::operation::delete_outbound_connection::builders::DeleteOutboundConnectionInputBuilder::default()
    }
}

/// A builder for [`DeleteOutboundConnectionInput`](crate::operation::delete_outbound_connection::DeleteOutboundConnectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteOutboundConnectionInputBuilder {
    pub(crate) connection_id: ::std::option::Option<::std::string::String>,
}
impl DeleteOutboundConnectionInputBuilder {
    /// <p>The ID of the outbound connection you want to permanently delete.</p>
    /// This field is required.
    pub fn connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the outbound connection you want to permanently delete.</p>
    pub fn set_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_id = input;
        self
    }
    /// <p>The ID of the outbound connection you want to permanently delete.</p>
    pub fn get_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_id
    }
    /// Consumes the builder and constructs a [`DeleteOutboundConnectionInput`](crate::operation::delete_outbound_connection::DeleteOutboundConnectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_outbound_connection::DeleteOutboundConnectionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_outbound_connection::DeleteOutboundConnectionInput {
            connection_id: self.connection_id,
        })
    }
}
