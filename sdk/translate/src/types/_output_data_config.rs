// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output configuration properties for a batch translation job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OutputDataConfig {
    /// <p>The URI of the S3 folder that contains a translation job's output file. The folder must be in the same Region as the API endpoint that you are calling.</p>
    pub s3_uri: ::std::string::String,
    /// <p>The encryption key used to encrypt this object.</p>
    pub encryption_key: ::std::option::Option<crate::types::EncryptionKey>,
}
impl OutputDataConfig {
    /// <p>The URI of the S3 folder that contains a translation job's output file. The folder must be in the same Region as the API endpoint that you are calling.</p>
    pub fn s3_uri(&self) -> &str {
        use std::ops::Deref;
        self.s3_uri.deref()
    }
    /// <p>The encryption key used to encrypt this object.</p>
    pub fn encryption_key(&self) -> ::std::option::Option<&crate::types::EncryptionKey> {
        self.encryption_key.as_ref()
    }
}
impl OutputDataConfig {
    /// Creates a new builder-style object to manufacture [`OutputDataConfig`](crate::types::OutputDataConfig).
    pub fn builder() -> crate::types::builders::OutputDataConfigBuilder {
        crate::types::builders::OutputDataConfigBuilder::default()
    }
}

/// A builder for [`OutputDataConfig`](crate::types::OutputDataConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OutputDataConfigBuilder {
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) encryption_key: ::std::option::Option<crate::types::EncryptionKey>,
}
impl OutputDataConfigBuilder {
    /// <p>The URI of the S3 folder that contains a translation job's output file. The folder must be in the same Region as the API endpoint that you are calling.</p>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI of the S3 folder that contains a translation job's output file. The folder must be in the same Region as the API endpoint that you are calling.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>The URI of the S3 folder that contains a translation job's output file. The folder must be in the same Region as the API endpoint that you are calling.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// <p>The encryption key used to encrypt this object.</p>
    pub fn encryption_key(mut self, input: crate::types::EncryptionKey) -> Self {
        self.encryption_key = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption key used to encrypt this object.</p>
    pub fn set_encryption_key(mut self, input: ::std::option::Option<crate::types::EncryptionKey>) -> Self {
        self.encryption_key = input;
        self
    }
    /// <p>The encryption key used to encrypt this object.</p>
    pub fn get_encryption_key(&self) -> &::std::option::Option<crate::types::EncryptionKey> {
        &self.encryption_key
    }
    /// Consumes the builder and constructs a [`OutputDataConfig`](crate::types::OutputDataConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`s3_uri`](crate::types::builders::OutputDataConfigBuilder::s3_uri)
    pub fn build(self) -> ::std::result::Result<crate::types::OutputDataConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OutputDataConfig {
            s3_uri: self.s3_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_uri",
                    "s3_uri was not specified but it is required when building OutputDataConfig",
                )
            })?,
            encryption_key: self.encryption_key,
        })
    }
}
