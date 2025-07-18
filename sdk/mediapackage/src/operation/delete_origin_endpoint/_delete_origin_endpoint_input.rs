// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteOriginEndpointInput {
    /// The ID of the OriginEndpoint to delete.
    pub id: ::std::option::Option<::std::string::String>,
}
impl DeleteOriginEndpointInput {
    /// The ID of the OriginEndpoint to delete.
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl DeleteOriginEndpointInput {
    /// Creates a new builder-style object to manufacture [`DeleteOriginEndpointInput`](crate::operation::delete_origin_endpoint::DeleteOriginEndpointInput).
    pub fn builder() -> crate::operation::delete_origin_endpoint::builders::DeleteOriginEndpointInputBuilder {
        crate::operation::delete_origin_endpoint::builders::DeleteOriginEndpointInputBuilder::default()
    }
}

/// A builder for [`DeleteOriginEndpointInput`](crate::operation::delete_origin_endpoint::DeleteOriginEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteOriginEndpointInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl DeleteOriginEndpointInputBuilder {
    /// The ID of the OriginEndpoint to delete.
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the OriginEndpoint to delete.
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// The ID of the OriginEndpoint to delete.
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`DeleteOriginEndpointInput`](crate::operation::delete_origin_endpoint::DeleteOriginEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_origin_endpoint::DeleteOriginEndpointInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_origin_endpoint::DeleteOriginEndpointInput { id: self.id })
    }
}
