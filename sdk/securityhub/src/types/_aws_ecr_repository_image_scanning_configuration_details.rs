// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The image scanning configuration for a repository.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEcrRepositoryImageScanningConfigurationDetails {
    /// <p>Whether to scan images after they are pushed to a repository.</p>
    pub scan_on_push: ::std::option::Option<bool>,
}
impl AwsEcrRepositoryImageScanningConfigurationDetails {
    /// <p>Whether to scan images after they are pushed to a repository.</p>
    pub fn scan_on_push(&self) -> ::std::option::Option<bool> {
        self.scan_on_push
    }
}
impl AwsEcrRepositoryImageScanningConfigurationDetails {
    /// Creates a new builder-style object to manufacture [`AwsEcrRepositoryImageScanningConfigurationDetails`](crate::types::AwsEcrRepositoryImageScanningConfigurationDetails).
    pub fn builder() -> crate::types::builders::AwsEcrRepositoryImageScanningConfigurationDetailsBuilder {
        crate::types::builders::AwsEcrRepositoryImageScanningConfigurationDetailsBuilder::default()
    }
}

/// A builder for [`AwsEcrRepositoryImageScanningConfigurationDetails`](crate::types::AwsEcrRepositoryImageScanningConfigurationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEcrRepositoryImageScanningConfigurationDetailsBuilder {
    pub(crate) scan_on_push: ::std::option::Option<bool>,
}
impl AwsEcrRepositoryImageScanningConfigurationDetailsBuilder {
    /// <p>Whether to scan images after they are pushed to a repository.</p>
    pub fn scan_on_push(mut self, input: bool) -> Self {
        self.scan_on_push = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to scan images after they are pushed to a repository.</p>
    pub fn set_scan_on_push(mut self, input: ::std::option::Option<bool>) -> Self {
        self.scan_on_push = input;
        self
    }
    /// <p>Whether to scan images after they are pushed to a repository.</p>
    pub fn get_scan_on_push(&self) -> &::std::option::Option<bool> {
        &self.scan_on_push
    }
    /// Consumes the builder and constructs a [`AwsEcrRepositoryImageScanningConfigurationDetails`](crate::types::AwsEcrRepositoryImageScanningConfigurationDetails).
    pub fn build(self) -> crate::types::AwsEcrRepositoryImageScanningConfigurationDetails {
        crate::types::AwsEcrRepositoryImageScanningConfigurationDetails {
            scan_on_push: self.scan_on_push,
        }
    }
}
