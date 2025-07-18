// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAddressInput {
    /// <p>The automatically generated ID for a specific address.</p>
    pub address_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAddressInput {
    /// <p>The automatically generated ID for a specific address.</p>
    pub fn address_id(&self) -> ::std::option::Option<&str> {
        self.address_id.as_deref()
    }
}
impl DescribeAddressInput {
    /// Creates a new builder-style object to manufacture [`DescribeAddressInput`](crate::operation::describe_address::DescribeAddressInput).
    pub fn builder() -> crate::operation::describe_address::builders::DescribeAddressInputBuilder {
        crate::operation::describe_address::builders::DescribeAddressInputBuilder::default()
    }
}

/// A builder for [`DescribeAddressInput`](crate::operation::describe_address::DescribeAddressInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAddressInputBuilder {
    pub(crate) address_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAddressInputBuilder {
    /// <p>The automatically generated ID for a specific address.</p>
    /// This field is required.
    pub fn address_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The automatically generated ID for a specific address.</p>
    pub fn set_address_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address_id = input;
        self
    }
    /// <p>The automatically generated ID for a specific address.</p>
    pub fn get_address_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.address_id
    }
    /// Consumes the builder and constructs a [`DescribeAddressInput`](crate::operation::describe_address::DescribeAddressInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_address::DescribeAddressInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_address::DescribeAddressInput { address_id: self.address_id })
    }
}
