// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDevEndpointInput {
    /// <p>The name of the <code>DevEndpoint</code>.</p>
    pub endpoint_name: ::std::option::Option<::std::string::String>,
}
impl DeleteDevEndpointInput {
    /// <p>The name of the <code>DevEndpoint</code>.</p>
    pub fn endpoint_name(&self) -> ::std::option::Option<&str> {
        self.endpoint_name.as_deref()
    }
}
impl DeleteDevEndpointInput {
    /// Creates a new builder-style object to manufacture [`DeleteDevEndpointInput`](crate::operation::delete_dev_endpoint::DeleteDevEndpointInput).
    pub fn builder() -> crate::operation::delete_dev_endpoint::builders::DeleteDevEndpointInputBuilder {
        crate::operation::delete_dev_endpoint::builders::DeleteDevEndpointInputBuilder::default()
    }
}

/// A builder for [`DeleteDevEndpointInput`](crate::operation::delete_dev_endpoint::DeleteDevEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDevEndpointInputBuilder {
    pub(crate) endpoint_name: ::std::option::Option<::std::string::String>,
}
impl DeleteDevEndpointInputBuilder {
    /// <p>The name of the <code>DevEndpoint</code>.</p>
    /// This field is required.
    pub fn endpoint_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the <code>DevEndpoint</code>.</p>
    pub fn set_endpoint_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_name = input;
        self
    }
    /// <p>The name of the <code>DevEndpoint</code>.</p>
    pub fn get_endpoint_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_name
    }
    /// Consumes the builder and constructs a [`DeleteDevEndpointInput`](crate::operation::delete_dev_endpoint::DeleteDevEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_dev_endpoint::DeleteDevEndpointInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_dev_endpoint::DeleteDevEndpointInput {
            endpoint_name: self.endpoint_name,
        })
    }
}
