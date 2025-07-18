// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteEndpointInput {
    /// <p>The Amazon Resource Name (ARN) string that uniquely identifies the endpoint.</p>
    pub endpoint_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteEndpointInput {
    /// <p>The Amazon Resource Name (ARN) string that uniquely identifies the endpoint.</p>
    pub fn endpoint_arn(&self) -> ::std::option::Option<&str> {
        self.endpoint_arn.as_deref()
    }
}
impl DeleteEndpointInput {
    /// Creates a new builder-style object to manufacture [`DeleteEndpointInput`](crate::operation::delete_endpoint::DeleteEndpointInput).
    pub fn builder() -> crate::operation::delete_endpoint::builders::DeleteEndpointInputBuilder {
        crate::operation::delete_endpoint::builders::DeleteEndpointInputBuilder::default()
    }
}

/// A builder for [`DeleteEndpointInput`](crate::operation::delete_endpoint::DeleteEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteEndpointInputBuilder {
    pub(crate) endpoint_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteEndpointInputBuilder {
    /// <p>The Amazon Resource Name (ARN) string that uniquely identifies the endpoint.</p>
    /// This field is required.
    pub fn endpoint_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) string that uniquely identifies the endpoint.</p>
    pub fn set_endpoint_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) string that uniquely identifies the endpoint.</p>
    pub fn get_endpoint_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_arn
    }
    /// Consumes the builder and constructs a [`DeleteEndpointInput`](crate::operation::delete_endpoint::DeleteEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_endpoint::DeleteEndpointInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_endpoint::DeleteEndpointInput {
            endpoint_arn: self.endpoint_arn,
        })
    }
}
