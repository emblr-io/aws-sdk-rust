// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUsageProfileInput {
    /// <p>The name of the usage profile to delete.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeleteUsageProfileInput {
    /// <p>The name of the usage profile to delete.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DeleteUsageProfileInput {
    /// Creates a new builder-style object to manufacture [`DeleteUsageProfileInput`](crate::operation::delete_usage_profile::DeleteUsageProfileInput).
    pub fn builder() -> crate::operation::delete_usage_profile::builders::DeleteUsageProfileInputBuilder {
        crate::operation::delete_usage_profile::builders::DeleteUsageProfileInputBuilder::default()
    }
}

/// A builder for [`DeleteUsageProfileInput`](crate::operation::delete_usage_profile::DeleteUsageProfileInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteUsageProfileInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeleteUsageProfileInputBuilder {
    /// <p>The name of the usage profile to delete.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the usage profile to delete.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the usage profile to delete.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeleteUsageProfileInput`](crate::operation::delete_usage_profile::DeleteUsageProfileInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_usage_profile::DeleteUsageProfileInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_usage_profile::DeleteUsageProfileInput { name: self.name })
    }
}
