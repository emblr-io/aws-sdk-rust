// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteSourceNetworkInput {
    /// <p>ID of the Source Network to delete.</p>
    pub source_network_id: ::std::option::Option<::std::string::String>,
}
impl DeleteSourceNetworkInput {
    /// <p>ID of the Source Network to delete.</p>
    pub fn source_network_id(&self) -> ::std::option::Option<&str> {
        self.source_network_id.as_deref()
    }
}
impl DeleteSourceNetworkInput {
    /// Creates a new builder-style object to manufacture [`DeleteSourceNetworkInput`](crate::operation::delete_source_network::DeleteSourceNetworkInput).
    pub fn builder() -> crate::operation::delete_source_network::builders::DeleteSourceNetworkInputBuilder {
        crate::operation::delete_source_network::builders::DeleteSourceNetworkInputBuilder::default()
    }
}

/// A builder for [`DeleteSourceNetworkInput`](crate::operation::delete_source_network::DeleteSourceNetworkInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteSourceNetworkInputBuilder {
    pub(crate) source_network_id: ::std::option::Option<::std::string::String>,
}
impl DeleteSourceNetworkInputBuilder {
    /// <p>ID of the Source Network to delete.</p>
    /// This field is required.
    pub fn source_network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID of the Source Network to delete.</p>
    pub fn set_source_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_network_id = input;
        self
    }
    /// <p>ID of the Source Network to delete.</p>
    pub fn get_source_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_network_id
    }
    /// Consumes the builder and constructs a [`DeleteSourceNetworkInput`](crate::operation::delete_source_network::DeleteSourceNetworkInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_source_network::DeleteSourceNetworkInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_source_network::DeleteSourceNetworkInput {
            source_network_id: self.source_network_id,
        })
    }
}
