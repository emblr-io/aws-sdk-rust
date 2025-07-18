// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartClusterInput {
    /// <p>The ARN identifier of the elastic cluster.</p>
    pub cluster_arn: ::std::option::Option<::std::string::String>,
}
impl StartClusterInput {
    /// <p>The ARN identifier of the elastic cluster.</p>
    pub fn cluster_arn(&self) -> ::std::option::Option<&str> {
        self.cluster_arn.as_deref()
    }
}
impl StartClusterInput {
    /// Creates a new builder-style object to manufacture [`StartClusterInput`](crate::operation::start_cluster::StartClusterInput).
    pub fn builder() -> crate::operation::start_cluster::builders::StartClusterInputBuilder {
        crate::operation::start_cluster::builders::StartClusterInputBuilder::default()
    }
}

/// A builder for [`StartClusterInput`](crate::operation::start_cluster::StartClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartClusterInputBuilder {
    pub(crate) cluster_arn: ::std::option::Option<::std::string::String>,
}
impl StartClusterInputBuilder {
    /// <p>The ARN identifier of the elastic cluster.</p>
    /// This field is required.
    pub fn cluster_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN identifier of the elastic cluster.</p>
    pub fn set_cluster_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_arn = input;
        self
    }
    /// <p>The ARN identifier of the elastic cluster.</p>
    pub fn get_cluster_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_arn
    }
    /// Consumes the builder and constructs a [`StartClusterInput`](crate::operation::start_cluster::StartClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_cluster::StartClusterInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_cluster::StartClusterInput {
            cluster_arn: self.cluster_arn,
        })
    }
}
