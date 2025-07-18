// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResolverEndpointInput {
    /// <p>The ID of the Resolver endpoint that you want to get information about.</p>
    pub resolver_endpoint_id: ::std::option::Option<::std::string::String>,
}
impl GetResolverEndpointInput {
    /// <p>The ID of the Resolver endpoint that you want to get information about.</p>
    pub fn resolver_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.resolver_endpoint_id.as_deref()
    }
}
impl GetResolverEndpointInput {
    /// Creates a new builder-style object to manufacture [`GetResolverEndpointInput`](crate::operation::get_resolver_endpoint::GetResolverEndpointInput).
    pub fn builder() -> crate::operation::get_resolver_endpoint::builders::GetResolverEndpointInputBuilder {
        crate::operation::get_resolver_endpoint::builders::GetResolverEndpointInputBuilder::default()
    }
}

/// A builder for [`GetResolverEndpointInput`](crate::operation::get_resolver_endpoint::GetResolverEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResolverEndpointInputBuilder {
    pub(crate) resolver_endpoint_id: ::std::option::Option<::std::string::String>,
}
impl GetResolverEndpointInputBuilder {
    /// <p>The ID of the Resolver endpoint that you want to get information about.</p>
    /// This field is required.
    pub fn resolver_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resolver_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Resolver endpoint that you want to get information about.</p>
    pub fn set_resolver_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resolver_endpoint_id = input;
        self
    }
    /// <p>The ID of the Resolver endpoint that you want to get information about.</p>
    pub fn get_resolver_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resolver_endpoint_id
    }
    /// Consumes the builder and constructs a [`GetResolverEndpointInput`](crate::operation::get_resolver_endpoint::GetResolverEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_resolver_endpoint::GetResolverEndpointInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_resolver_endpoint::GetResolverEndpointInput {
            resolver_endpoint_id: self.resolver_endpoint_id,
        })
    }
}
