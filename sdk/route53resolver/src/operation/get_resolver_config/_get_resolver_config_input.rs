// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResolverConfigInput {
    /// <p>Resource ID of the Amazon VPC that you want to get information about.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
}
impl GetResolverConfigInput {
    /// <p>Resource ID of the Amazon VPC that you want to get information about.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
}
impl GetResolverConfigInput {
    /// Creates a new builder-style object to manufacture [`GetResolverConfigInput`](crate::operation::get_resolver_config::GetResolverConfigInput).
    pub fn builder() -> crate::operation::get_resolver_config::builders::GetResolverConfigInputBuilder {
        crate::operation::get_resolver_config::builders::GetResolverConfigInputBuilder::default()
    }
}

/// A builder for [`GetResolverConfigInput`](crate::operation::get_resolver_config::GetResolverConfigInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResolverConfigInputBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
}
impl GetResolverConfigInputBuilder {
    /// <p>Resource ID of the Amazon VPC that you want to get information about.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Resource ID of the Amazon VPC that you want to get information about.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>Resource ID of the Amazon VPC that you want to get information about.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// Consumes the builder and constructs a [`GetResolverConfigInput`](crate::operation::get_resolver_config::GetResolverConfigInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_resolver_config::GetResolverConfigInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_resolver_config::GetResolverConfigInput {
            resource_id: self.resource_id,
        })
    }
}
