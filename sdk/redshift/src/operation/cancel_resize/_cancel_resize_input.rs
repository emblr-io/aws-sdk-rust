// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelResizeInput {
    /// <p>The unique identifier for the cluster that you want to cancel a resize operation for.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
}
impl CancelResizeInput {
    /// <p>The unique identifier for the cluster that you want to cancel a resize operation for.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
}
impl CancelResizeInput {
    /// Creates a new builder-style object to manufacture [`CancelResizeInput`](crate::operation::cancel_resize::CancelResizeInput).
    pub fn builder() -> crate::operation::cancel_resize::builders::CancelResizeInputBuilder {
        crate::operation::cancel_resize::builders::CancelResizeInputBuilder::default()
    }
}

/// A builder for [`CancelResizeInput`](crate::operation::cancel_resize::CancelResizeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelResizeInputBuilder {
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
}
impl CancelResizeInputBuilder {
    /// <p>The unique identifier for the cluster that you want to cancel a resize operation for.</p>
    /// This field is required.
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the cluster that you want to cancel a resize operation for.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The unique identifier for the cluster that you want to cancel a resize operation for.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// Consumes the builder and constructs a [`CancelResizeInput`](crate::operation::cancel_resize::CancelResizeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_resize::CancelResizeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::cancel_resize::CancelResizeInput {
            cluster_identifier: self.cluster_identifier,
        })
    }
}
