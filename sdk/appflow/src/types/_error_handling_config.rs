// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The settings that determine how Amazon AppFlow handles an error when placing data in the destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. <code>ErrorHandlingConfig</code> is a part of the destination connector details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ErrorHandlingConfig {
    /// <p>Specifies if the flow should fail after the first instance of a failure when attempting to place data in the destination.</p>
    pub fail_on_first_destination_error: bool,
    /// <p>Specifies the Amazon S3 bucket prefix.</p>
    pub bucket_prefix: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the name of the Amazon S3 bucket.</p>
    pub bucket_name: ::std::option::Option<::std::string::String>,
}
impl ErrorHandlingConfig {
    /// <p>Specifies if the flow should fail after the first instance of a failure when attempting to place data in the destination.</p>
    pub fn fail_on_first_destination_error(&self) -> bool {
        self.fail_on_first_destination_error
    }
    /// <p>Specifies the Amazon S3 bucket prefix.</p>
    pub fn bucket_prefix(&self) -> ::std::option::Option<&str> {
        self.bucket_prefix.as_deref()
    }
    /// <p>Specifies the name of the Amazon S3 bucket.</p>
    pub fn bucket_name(&self) -> ::std::option::Option<&str> {
        self.bucket_name.as_deref()
    }
}
impl ErrorHandlingConfig {
    /// Creates a new builder-style object to manufacture [`ErrorHandlingConfig`](crate::types::ErrorHandlingConfig).
    pub fn builder() -> crate::types::builders::ErrorHandlingConfigBuilder {
        crate::types::builders::ErrorHandlingConfigBuilder::default()
    }
}

/// A builder for [`ErrorHandlingConfig`](crate::types::ErrorHandlingConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ErrorHandlingConfigBuilder {
    pub(crate) fail_on_first_destination_error: ::std::option::Option<bool>,
    pub(crate) bucket_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) bucket_name: ::std::option::Option<::std::string::String>,
}
impl ErrorHandlingConfigBuilder {
    /// <p>Specifies if the flow should fail after the first instance of a failure when attempting to place data in the destination.</p>
    pub fn fail_on_first_destination_error(mut self, input: bool) -> Self {
        self.fail_on_first_destination_error = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if the flow should fail after the first instance of a failure when attempting to place data in the destination.</p>
    pub fn set_fail_on_first_destination_error(mut self, input: ::std::option::Option<bool>) -> Self {
        self.fail_on_first_destination_error = input;
        self
    }
    /// <p>Specifies if the flow should fail after the first instance of a failure when attempting to place data in the destination.</p>
    pub fn get_fail_on_first_destination_error(&self) -> &::std::option::Option<bool> {
        &self.fail_on_first_destination_error
    }
    /// <p>Specifies the Amazon S3 bucket prefix.</p>
    pub fn bucket_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the Amazon S3 bucket prefix.</p>
    pub fn set_bucket_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_prefix = input;
        self
    }
    /// <p>Specifies the Amazon S3 bucket prefix.</p>
    pub fn get_bucket_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_prefix
    }
    /// <p>Specifies the name of the Amazon S3 bucket.</p>
    pub fn bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the name of the Amazon S3 bucket.</p>
    pub fn set_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_name = input;
        self
    }
    /// <p>Specifies the name of the Amazon S3 bucket.</p>
    pub fn get_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_name
    }
    /// Consumes the builder and constructs a [`ErrorHandlingConfig`](crate::types::ErrorHandlingConfig).
    pub fn build(self) -> crate::types::ErrorHandlingConfig {
        crate::types::ErrorHandlingConfig {
            fail_on_first_destination_error: self.fail_on_first_destination_error.unwrap_or_default(),
            bucket_prefix: self.bucket_prefix,
            bucket_name: self.bucket_name,
        }
    }
}
