// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The current configuration of S3 data event logs as a data source for the organization.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OrganizationS3LogsConfigurationResult {
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    pub auto_enable: ::std::option::Option<bool>,
}
impl OrganizationS3LogsConfigurationResult {
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    pub fn auto_enable(&self) -> ::std::option::Option<bool> {
        self.auto_enable
    }
}
impl OrganizationS3LogsConfigurationResult {
    /// Creates a new builder-style object to manufacture [`OrganizationS3LogsConfigurationResult`](crate::types::OrganizationS3LogsConfigurationResult).
    pub fn builder() -> crate::types::builders::OrganizationS3LogsConfigurationResultBuilder {
        crate::types::builders::OrganizationS3LogsConfigurationResultBuilder::default()
    }
}

/// A builder for [`OrganizationS3LogsConfigurationResult`](crate::types::OrganizationS3LogsConfigurationResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OrganizationS3LogsConfigurationResultBuilder {
    pub(crate) auto_enable: ::std::option::Option<bool>,
}
impl OrganizationS3LogsConfigurationResultBuilder {
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    /// This field is required.
    pub fn auto_enable(mut self, input: bool) -> Self {
        self.auto_enable = ::std::option::Option::Some(input);
        self
    }
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    pub fn set_auto_enable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.auto_enable = input;
        self
    }
    /// <p>A value that describes whether S3 data event logs are automatically enabled for new members of the organization.</p>
    pub fn get_auto_enable(&self) -> &::std::option::Option<bool> {
        &self.auto_enable
    }
    /// Consumes the builder and constructs a [`OrganizationS3LogsConfigurationResult`](crate::types::OrganizationS3LogsConfigurationResult).
    pub fn build(self) -> crate::types::OrganizationS3LogsConfigurationResult {
        crate::types::OrganizationS3LogsConfigurationResult {
            auto_enable: self.auto_enable,
        }
    }
}
