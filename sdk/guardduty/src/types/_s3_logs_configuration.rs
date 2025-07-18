// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes whether S3 data event logs will be enabled as a data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3LogsConfiguration {
    /// <p>The status of S3 data event logs as a data source.</p>
    pub enable: ::std::option::Option<bool>,
}
impl S3LogsConfiguration {
    /// <p>The status of S3 data event logs as a data source.</p>
    pub fn enable(&self) -> ::std::option::Option<bool> {
        self.enable
    }
}
impl S3LogsConfiguration {
    /// Creates a new builder-style object to manufacture [`S3LogsConfiguration`](crate::types::S3LogsConfiguration).
    pub fn builder() -> crate::types::builders::S3LogsConfigurationBuilder {
        crate::types::builders::S3LogsConfigurationBuilder::default()
    }
}

/// A builder for [`S3LogsConfiguration`](crate::types::S3LogsConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3LogsConfigurationBuilder {
    pub(crate) enable: ::std::option::Option<bool>,
}
impl S3LogsConfigurationBuilder {
    /// <p>The status of S3 data event logs as a data source.</p>
    /// This field is required.
    pub fn enable(mut self, input: bool) -> Self {
        self.enable = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of S3 data event logs as a data source.</p>
    pub fn set_enable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable = input;
        self
    }
    /// <p>The status of S3 data event logs as a data source.</p>
    pub fn get_enable(&self) -> &::std::option::Option<bool> {
        &self.enable
    }
    /// Consumes the builder and constructs a [`S3LogsConfiguration`](crate::types::S3LogsConfiguration).
    pub fn build(self) -> crate::types::S3LogsConfiguration {
        crate::types::S3LogsConfiguration { enable: self.enable }
    }
}
