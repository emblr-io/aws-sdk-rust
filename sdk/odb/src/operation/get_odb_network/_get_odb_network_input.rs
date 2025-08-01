// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOdbNetworkInput {
    /// <p>The unique identifier of the ODB network.</p>
    pub odb_network_id: ::std::option::Option<::std::string::String>,
}
impl GetOdbNetworkInput {
    /// <p>The unique identifier of the ODB network.</p>
    pub fn odb_network_id(&self) -> ::std::option::Option<&str> {
        self.odb_network_id.as_deref()
    }
}
impl GetOdbNetworkInput {
    /// Creates a new builder-style object to manufacture [`GetOdbNetworkInput`](crate::operation::get_odb_network::GetOdbNetworkInput).
    pub fn builder() -> crate::operation::get_odb_network::builders::GetOdbNetworkInputBuilder {
        crate::operation::get_odb_network::builders::GetOdbNetworkInputBuilder::default()
    }
}

/// A builder for [`GetOdbNetworkInput`](crate::operation::get_odb_network::GetOdbNetworkInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOdbNetworkInputBuilder {
    pub(crate) odb_network_id: ::std::option::Option<::std::string::String>,
}
impl GetOdbNetworkInputBuilder {
    /// <p>The unique identifier of the ODB network.</p>
    /// This field is required.
    pub fn odb_network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.odb_network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the ODB network.</p>
    pub fn set_odb_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.odb_network_id = input;
        self
    }
    /// <p>The unique identifier of the ODB network.</p>
    pub fn get_odb_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.odb_network_id
    }
    /// Consumes the builder and constructs a [`GetOdbNetworkInput`](crate::operation::get_odb_network::GetOdbNetworkInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_odb_network::GetOdbNetworkInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_odb_network::GetOdbNetworkInput {
            odb_network_id: self.odb_network_id,
        })
    }
}
