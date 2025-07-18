// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the Python scripts used for entry and by an Amazon Braket job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScriptModeConfig {
    /// <p>The path to the Python script that serves as the entry point for an Amazon Braket job.</p>
    pub entry_point: ::std::string::String,
    /// <p>The URI that specifies the S3 path to the Python script module that contains the training script used by an Amazon Braket job.</p>
    pub s3_uri: ::std::string::String,
    /// <p>The type of compression used by the Python scripts for an Amazon Braket job.</p>
    pub compression_type: ::std::option::Option<crate::types::CompressionType>,
}
impl ScriptModeConfig {
    /// <p>The path to the Python script that serves as the entry point for an Amazon Braket job.</p>
    pub fn entry_point(&self) -> &str {
        use std::ops::Deref;
        self.entry_point.deref()
    }
    /// <p>The URI that specifies the S3 path to the Python script module that contains the training script used by an Amazon Braket job.</p>
    pub fn s3_uri(&self) -> &str {
        use std::ops::Deref;
        self.s3_uri.deref()
    }
    /// <p>The type of compression used by the Python scripts for an Amazon Braket job.</p>
    pub fn compression_type(&self) -> ::std::option::Option<&crate::types::CompressionType> {
        self.compression_type.as_ref()
    }
}
impl ScriptModeConfig {
    /// Creates a new builder-style object to manufacture [`ScriptModeConfig`](crate::types::ScriptModeConfig).
    pub fn builder() -> crate::types::builders::ScriptModeConfigBuilder {
        crate::types::builders::ScriptModeConfigBuilder::default()
    }
}

/// A builder for [`ScriptModeConfig`](crate::types::ScriptModeConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScriptModeConfigBuilder {
    pub(crate) entry_point: ::std::option::Option<::std::string::String>,
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) compression_type: ::std::option::Option<crate::types::CompressionType>,
}
impl ScriptModeConfigBuilder {
    /// <p>The path to the Python script that serves as the entry point for an Amazon Braket job.</p>
    /// This field is required.
    pub fn entry_point(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entry_point = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the Python script that serves as the entry point for an Amazon Braket job.</p>
    pub fn set_entry_point(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entry_point = input;
        self
    }
    /// <p>The path to the Python script that serves as the entry point for an Amazon Braket job.</p>
    pub fn get_entry_point(&self) -> &::std::option::Option<::std::string::String> {
        &self.entry_point
    }
    /// <p>The URI that specifies the S3 path to the Python script module that contains the training script used by an Amazon Braket job.</p>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI that specifies the S3 path to the Python script module that contains the training script used by an Amazon Braket job.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>The URI that specifies the S3 path to the Python script module that contains the training script used by an Amazon Braket job.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// <p>The type of compression used by the Python scripts for an Amazon Braket job.</p>
    pub fn compression_type(mut self, input: crate::types::CompressionType) -> Self {
        self.compression_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of compression used by the Python scripts for an Amazon Braket job.</p>
    pub fn set_compression_type(mut self, input: ::std::option::Option<crate::types::CompressionType>) -> Self {
        self.compression_type = input;
        self
    }
    /// <p>The type of compression used by the Python scripts for an Amazon Braket job.</p>
    pub fn get_compression_type(&self) -> &::std::option::Option<crate::types::CompressionType> {
        &self.compression_type
    }
    /// Consumes the builder and constructs a [`ScriptModeConfig`](crate::types::ScriptModeConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`entry_point`](crate::types::builders::ScriptModeConfigBuilder::entry_point)
    /// - [`s3_uri`](crate::types::builders::ScriptModeConfigBuilder::s3_uri)
    pub fn build(self) -> ::std::result::Result<crate::types::ScriptModeConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ScriptModeConfig {
            entry_point: self.entry_point.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "entry_point",
                    "entry_point was not specified but it is required when building ScriptModeConfig",
                )
            })?,
            s3_uri: self.s3_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_uri",
                    "s3_uri was not specified but it is required when building ScriptModeConfig",
                )
            })?,
            compression_type: self.compression_type,
        })
    }
}
