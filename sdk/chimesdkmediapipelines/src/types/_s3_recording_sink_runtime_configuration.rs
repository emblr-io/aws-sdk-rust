// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that holds the settings for transmitting media files to the Amazon S3 bucket. If specified, the settings in this structure override any settings in <code>S3RecordingSinkConfiguration</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct S3RecordingSinkRuntimeConfiguration {
    /// <p>The URI of the S3 bucket used as the sink.</p>
    pub destination: ::std::string::String,
    /// <p>The file format for the media files sent to the Amazon S3 bucket.</p>
    pub recording_file_format: crate::types::RecordingFileFormat,
}
impl S3RecordingSinkRuntimeConfiguration {
    /// <p>The URI of the S3 bucket used as the sink.</p>
    pub fn destination(&self) -> &str {
        use std::ops::Deref;
        self.destination.deref()
    }
    /// <p>The file format for the media files sent to the Amazon S3 bucket.</p>
    pub fn recording_file_format(&self) -> &crate::types::RecordingFileFormat {
        &self.recording_file_format
    }
}
impl ::std::fmt::Debug for S3RecordingSinkRuntimeConfiguration {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("S3RecordingSinkRuntimeConfiguration");
        formatter.field("destination", &"*** Sensitive Data Redacted ***");
        formatter.field("recording_file_format", &self.recording_file_format);
        formatter.finish()
    }
}
impl S3RecordingSinkRuntimeConfiguration {
    /// Creates a new builder-style object to manufacture [`S3RecordingSinkRuntimeConfiguration`](crate::types::S3RecordingSinkRuntimeConfiguration).
    pub fn builder() -> crate::types::builders::S3RecordingSinkRuntimeConfigurationBuilder {
        crate::types::builders::S3RecordingSinkRuntimeConfigurationBuilder::default()
    }
}

/// A builder for [`S3RecordingSinkRuntimeConfiguration`](crate::types::S3RecordingSinkRuntimeConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct S3RecordingSinkRuntimeConfigurationBuilder {
    pub(crate) destination: ::std::option::Option<::std::string::String>,
    pub(crate) recording_file_format: ::std::option::Option<crate::types::RecordingFileFormat>,
}
impl S3RecordingSinkRuntimeConfigurationBuilder {
    /// <p>The URI of the S3 bucket used as the sink.</p>
    /// This field is required.
    pub fn destination(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI of the S3 bucket used as the sink.</p>
    pub fn set_destination(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination = input;
        self
    }
    /// <p>The URI of the S3 bucket used as the sink.</p>
    pub fn get_destination(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination
    }
    /// <p>The file format for the media files sent to the Amazon S3 bucket.</p>
    /// This field is required.
    pub fn recording_file_format(mut self, input: crate::types::RecordingFileFormat) -> Self {
        self.recording_file_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The file format for the media files sent to the Amazon S3 bucket.</p>
    pub fn set_recording_file_format(mut self, input: ::std::option::Option<crate::types::RecordingFileFormat>) -> Self {
        self.recording_file_format = input;
        self
    }
    /// <p>The file format for the media files sent to the Amazon S3 bucket.</p>
    pub fn get_recording_file_format(&self) -> &::std::option::Option<crate::types::RecordingFileFormat> {
        &self.recording_file_format
    }
    /// Consumes the builder and constructs a [`S3RecordingSinkRuntimeConfiguration`](crate::types::S3RecordingSinkRuntimeConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`destination`](crate::types::builders::S3RecordingSinkRuntimeConfigurationBuilder::destination)
    /// - [`recording_file_format`](crate::types::builders::S3RecordingSinkRuntimeConfigurationBuilder::recording_file_format)
    pub fn build(self) -> ::std::result::Result<crate::types::S3RecordingSinkRuntimeConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3RecordingSinkRuntimeConfiguration {
            destination: self.destination.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "destination",
                    "destination was not specified but it is required when building S3RecordingSinkRuntimeConfiguration",
                )
            })?,
            recording_file_format: self.recording_file_format.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "recording_file_format",
                    "recording_file_format was not specified but it is required when building S3RecordingSinkRuntimeConfiguration",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for S3RecordingSinkRuntimeConfigurationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("S3RecordingSinkRuntimeConfigurationBuilder");
        formatter.field("destination", &"*** Sensitive Data Redacted ***");
        formatter.field("recording_file_format", &self.recording_file_format);
        formatter.finish()
    }
}
