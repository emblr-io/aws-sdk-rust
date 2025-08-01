// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration information for pre-signed URLs. Valid when <code>protocols</code> contains HTTP.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsJobPresignedUrlConfig {
    /// <p>How long (in seconds) pre-signed URLs are valid. Valid values are 60 - 3600, the default value is 1800 seconds. Pre-signed URLs are generated when a request for the job document is received.</p>
    pub expires_in_sec: ::std::option::Option<i64>,
}
impl AwsJobPresignedUrlConfig {
    /// <p>How long (in seconds) pre-signed URLs are valid. Valid values are 60 - 3600, the default value is 1800 seconds. Pre-signed URLs are generated when a request for the job document is received.</p>
    pub fn expires_in_sec(&self) -> ::std::option::Option<i64> {
        self.expires_in_sec
    }
}
impl AwsJobPresignedUrlConfig {
    /// Creates a new builder-style object to manufacture [`AwsJobPresignedUrlConfig`](crate::types::AwsJobPresignedUrlConfig).
    pub fn builder() -> crate::types::builders::AwsJobPresignedUrlConfigBuilder {
        crate::types::builders::AwsJobPresignedUrlConfigBuilder::default()
    }
}

/// A builder for [`AwsJobPresignedUrlConfig`](crate::types::AwsJobPresignedUrlConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsJobPresignedUrlConfigBuilder {
    pub(crate) expires_in_sec: ::std::option::Option<i64>,
}
impl AwsJobPresignedUrlConfigBuilder {
    /// <p>How long (in seconds) pre-signed URLs are valid. Valid values are 60 - 3600, the default value is 1800 seconds. Pre-signed URLs are generated when a request for the job document is received.</p>
    pub fn expires_in_sec(mut self, input: i64) -> Self {
        self.expires_in_sec = ::std::option::Option::Some(input);
        self
    }
    /// <p>How long (in seconds) pre-signed URLs are valid. Valid values are 60 - 3600, the default value is 1800 seconds. Pre-signed URLs are generated when a request for the job document is received.</p>
    pub fn set_expires_in_sec(mut self, input: ::std::option::Option<i64>) -> Self {
        self.expires_in_sec = input;
        self
    }
    /// <p>How long (in seconds) pre-signed URLs are valid. Valid values are 60 - 3600, the default value is 1800 seconds. Pre-signed URLs are generated when a request for the job document is received.</p>
    pub fn get_expires_in_sec(&self) -> &::std::option::Option<i64> {
        &self.expires_in_sec
    }
    /// Consumes the builder and constructs a [`AwsJobPresignedUrlConfig`](crate::types::AwsJobPresignedUrlConfig).
    pub fn build(self) -> crate::types::AwsJobPresignedUrlConfig {
        crate::types::AwsJobPresignedUrlConfig {
            expires_in_sec: self.expires_in_sec,
        }
    }
}
