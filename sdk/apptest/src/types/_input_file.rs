// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the input file.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InputFile {
    /// <p>The source location of the input file.</p>
    pub source_location: ::std::string::String,
    /// <p>The target location of the input file.</p>
    pub target_location: ::std::string::String,
    /// <p>The file metadata of the input file.</p>
    pub file_metadata: ::std::option::Option<crate::types::FileMetadata>,
}
impl InputFile {
    /// <p>The source location of the input file.</p>
    pub fn source_location(&self) -> &str {
        use std::ops::Deref;
        self.source_location.deref()
    }
    /// <p>The target location of the input file.</p>
    pub fn target_location(&self) -> &str {
        use std::ops::Deref;
        self.target_location.deref()
    }
    /// <p>The file metadata of the input file.</p>
    pub fn file_metadata(&self) -> ::std::option::Option<&crate::types::FileMetadata> {
        self.file_metadata.as_ref()
    }
}
impl InputFile {
    /// Creates a new builder-style object to manufacture [`InputFile`](crate::types::InputFile).
    pub fn builder() -> crate::types::builders::InputFileBuilder {
        crate::types::builders::InputFileBuilder::default()
    }
}

/// A builder for [`InputFile`](crate::types::InputFile).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InputFileBuilder {
    pub(crate) source_location: ::std::option::Option<::std::string::String>,
    pub(crate) target_location: ::std::option::Option<::std::string::String>,
    pub(crate) file_metadata: ::std::option::Option<crate::types::FileMetadata>,
}
impl InputFileBuilder {
    /// <p>The source location of the input file.</p>
    /// This field is required.
    pub fn source_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source location of the input file.</p>
    pub fn set_source_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_location = input;
        self
    }
    /// <p>The source location of the input file.</p>
    pub fn get_source_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_location
    }
    /// <p>The target location of the input file.</p>
    /// This field is required.
    pub fn target_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The target location of the input file.</p>
    pub fn set_target_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_location = input;
        self
    }
    /// <p>The target location of the input file.</p>
    pub fn get_target_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_location
    }
    /// <p>The file metadata of the input file.</p>
    /// This field is required.
    pub fn file_metadata(mut self, input: crate::types::FileMetadata) -> Self {
        self.file_metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>The file metadata of the input file.</p>
    pub fn set_file_metadata(mut self, input: ::std::option::Option<crate::types::FileMetadata>) -> Self {
        self.file_metadata = input;
        self
    }
    /// <p>The file metadata of the input file.</p>
    pub fn get_file_metadata(&self) -> &::std::option::Option<crate::types::FileMetadata> {
        &self.file_metadata
    }
    /// Consumes the builder and constructs a [`InputFile`](crate::types::InputFile).
    /// This method will fail if any of the following fields are not set:
    /// - [`source_location`](crate::types::builders::InputFileBuilder::source_location)
    /// - [`target_location`](crate::types::builders::InputFileBuilder::target_location)
    pub fn build(self) -> ::std::result::Result<crate::types::InputFile, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InputFile {
            source_location: self.source_location.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source_location",
                    "source_location was not specified but it is required when building InputFile",
                )
            })?,
            target_location: self.target_location.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "target_location",
                    "target_location was not specified but it is required when building InputFile",
                )
            })?,
            file_metadata: self.file_metadata,
        })
    }
}
