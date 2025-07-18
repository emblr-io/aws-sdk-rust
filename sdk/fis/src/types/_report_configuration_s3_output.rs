// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the S3 destination for the experiment report.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReportConfigurationS3Output {
    /// <p>The name of the S3 bucket where the experiment report will be stored.</p>
    pub bucket_name: ::std::option::Option<::std::string::String>,
    /// <p>The prefix of the S3 bucket where the experiment report will be stored.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
}
impl ReportConfigurationS3Output {
    /// <p>The name of the S3 bucket where the experiment report will be stored.</p>
    pub fn bucket_name(&self) -> ::std::option::Option<&str> {
        self.bucket_name.as_deref()
    }
    /// <p>The prefix of the S3 bucket where the experiment report will be stored.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
}
impl ReportConfigurationS3Output {
    /// Creates a new builder-style object to manufacture [`ReportConfigurationS3Output`](crate::types::ReportConfigurationS3Output).
    pub fn builder() -> crate::types::builders::ReportConfigurationS3OutputBuilder {
        crate::types::builders::ReportConfigurationS3OutputBuilder::default()
    }
}

/// A builder for [`ReportConfigurationS3Output`](crate::types::ReportConfigurationS3Output).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReportConfigurationS3OutputBuilder {
    pub(crate) bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
}
impl ReportConfigurationS3OutputBuilder {
    /// <p>The name of the S3 bucket where the experiment report will be stored.</p>
    pub fn bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the S3 bucket where the experiment report will be stored.</p>
    pub fn set_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_name = input;
        self
    }
    /// <p>The name of the S3 bucket where the experiment report will be stored.</p>
    pub fn get_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_name
    }
    /// <p>The prefix of the S3 bucket where the experiment report will be stored.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prefix of the S3 bucket where the experiment report will be stored.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>The prefix of the S3 bucket where the experiment report will be stored.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// Consumes the builder and constructs a [`ReportConfigurationS3Output`](crate::types::ReportConfigurationS3Output).
    pub fn build(self) -> crate::types::ReportConfigurationS3Output {
        crate::types::ReportConfigurationS3Output {
            bucket_name: self.bucket_name,
            prefix: self.prefix,
        }
    }
}
