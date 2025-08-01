// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A cluster whose updates have failed</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnprocessedCluster {
    /// <p>The name of the cluster</p>
    pub cluster_name: ::std::option::Option<::std::string::String>,
    /// <p>The error type associated with the update failure</p>
    pub error_type: ::std::option::Option<::std::string::String>,
    /// <p>The error message associated with the update failure</p>
    pub error_message: ::std::option::Option<::std::string::String>,
}
impl UnprocessedCluster {
    /// <p>The name of the cluster</p>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
    /// <p>The error type associated with the update failure</p>
    pub fn error_type(&self) -> ::std::option::Option<&str> {
        self.error_type.as_deref()
    }
    /// <p>The error message associated with the update failure</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
}
impl UnprocessedCluster {
    /// Creates a new builder-style object to manufacture [`UnprocessedCluster`](crate::types::UnprocessedCluster).
    pub fn builder() -> crate::types::builders::UnprocessedClusterBuilder {
        crate::types::builders::UnprocessedClusterBuilder::default()
    }
}

/// A builder for [`UnprocessedCluster`](crate::types::UnprocessedCluster).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnprocessedClusterBuilder {
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
    pub(crate) error_type: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
}
impl UnprocessedClusterBuilder {
    /// <p>The name of the cluster</p>
    pub fn cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster</p>
    pub fn set_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_name = input;
        self
    }
    /// <p>The name of the cluster</p>
    pub fn get_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_name
    }
    /// <p>The error type associated with the update failure</p>
    pub fn error_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error type associated with the update failure</p>
    pub fn set_error_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_type = input;
        self
    }
    /// <p>The error type associated with the update failure</p>
    pub fn get_error_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_type
    }
    /// <p>The error message associated with the update failure</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message associated with the update failure</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The error message associated with the update failure</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Consumes the builder and constructs a [`UnprocessedCluster`](crate::types::UnprocessedCluster).
    pub fn build(self) -> crate::types::UnprocessedCluster {
        crate::types::UnprocessedCluster {
            cluster_name: self.cluster_name,
            error_type: self.error_type,
            error_message: self.error_message,
        }
    }
}
