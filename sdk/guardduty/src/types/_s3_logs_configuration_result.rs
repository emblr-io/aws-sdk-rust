// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes whether S3 data event logs will be enabled as a data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3LogsConfigurationResult {
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    pub status: ::std::option::Option<crate::types::DataSourceStatus>,
}
impl S3LogsConfigurationResult {
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DataSourceStatus> {
        self.status.as_ref()
    }
}
impl S3LogsConfigurationResult {
    /// Creates a new builder-style object to manufacture [`S3LogsConfigurationResult`](crate::types::S3LogsConfigurationResult).
    pub fn builder() -> crate::types::builders::S3LogsConfigurationResultBuilder {
        crate::types::builders::S3LogsConfigurationResultBuilder::default()
    }
}

/// A builder for [`S3LogsConfigurationResult`](crate::types::S3LogsConfigurationResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3LogsConfigurationResultBuilder {
    pub(crate) status: ::std::option::Option<crate::types::DataSourceStatus>,
}
impl S3LogsConfigurationResultBuilder {
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::DataSourceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DataSourceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DataSourceStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`S3LogsConfigurationResult`](crate::types::S3LogsConfigurationResult).
    pub fn build(self) -> crate::types::S3LogsConfigurationResult {
        crate::types::S3LogsConfigurationResult { status: self.status }
    }
}
