// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeQueryLoggingConfigurationOutput {
    /// <p>The detailed information about the query logging configuration for the specified workspace.</p>
    pub query_logging_configuration: ::std::option::Option<crate::types::QueryLoggingConfigurationMetadata>,
    _request_id: Option<String>,
}
impl DescribeQueryLoggingConfigurationOutput {
    /// <p>The detailed information about the query logging configuration for the specified workspace.</p>
    pub fn query_logging_configuration(&self) -> ::std::option::Option<&crate::types::QueryLoggingConfigurationMetadata> {
        self.query_logging_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeQueryLoggingConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeQueryLoggingConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeQueryLoggingConfigurationOutput`](crate::operation::describe_query_logging_configuration::DescribeQueryLoggingConfigurationOutput).
    pub fn builder() -> crate::operation::describe_query_logging_configuration::builders::DescribeQueryLoggingConfigurationOutputBuilder {
        crate::operation::describe_query_logging_configuration::builders::DescribeQueryLoggingConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DescribeQueryLoggingConfigurationOutput`](crate::operation::describe_query_logging_configuration::DescribeQueryLoggingConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeQueryLoggingConfigurationOutputBuilder {
    pub(crate) query_logging_configuration: ::std::option::Option<crate::types::QueryLoggingConfigurationMetadata>,
    _request_id: Option<String>,
}
impl DescribeQueryLoggingConfigurationOutputBuilder {
    /// <p>The detailed information about the query logging configuration for the specified workspace.</p>
    /// This field is required.
    pub fn query_logging_configuration(mut self, input: crate::types::QueryLoggingConfigurationMetadata) -> Self {
        self.query_logging_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The detailed information about the query logging configuration for the specified workspace.</p>
    pub fn set_query_logging_configuration(mut self, input: ::std::option::Option<crate::types::QueryLoggingConfigurationMetadata>) -> Self {
        self.query_logging_configuration = input;
        self
    }
    /// <p>The detailed information about the query logging configuration for the specified workspace.</p>
    pub fn get_query_logging_configuration(&self) -> &::std::option::Option<crate::types::QueryLoggingConfigurationMetadata> {
        &self.query_logging_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeQueryLoggingConfigurationOutput`](crate::operation::describe_query_logging_configuration::DescribeQueryLoggingConfigurationOutput).
    pub fn build(self) -> crate::operation::describe_query_logging_configuration::DescribeQueryLoggingConfigurationOutput {
        crate::operation::describe_query_logging_configuration::DescribeQueryLoggingConfigurationOutput {
            query_logging_configuration: self.query_logging_configuration,
            _request_id: self._request_id,
        }
    }
}
