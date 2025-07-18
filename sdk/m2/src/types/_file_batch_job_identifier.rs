// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A batch job identifier in which the batch job to run is identified by the file name and the relative path to the file name.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FileBatchJobIdentifier {
    /// <p>The file name for the batch job identifier.</p>
    pub file_name: ::std::string::String,
    /// <p>The relative path to the file name for the batch job identifier.</p>
    pub folder_path: ::std::option::Option<::std::string::String>,
}
impl FileBatchJobIdentifier {
    /// <p>The file name for the batch job identifier.</p>
    pub fn file_name(&self) -> &str {
        use std::ops::Deref;
        self.file_name.deref()
    }
    /// <p>The relative path to the file name for the batch job identifier.</p>
    pub fn folder_path(&self) -> ::std::option::Option<&str> {
        self.folder_path.as_deref()
    }
}
impl FileBatchJobIdentifier {
    /// Creates a new builder-style object to manufacture [`FileBatchJobIdentifier`](crate::types::FileBatchJobIdentifier).
    pub fn builder() -> crate::types::builders::FileBatchJobIdentifierBuilder {
        crate::types::builders::FileBatchJobIdentifierBuilder::default()
    }
}

/// A builder for [`FileBatchJobIdentifier`](crate::types::FileBatchJobIdentifier).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FileBatchJobIdentifierBuilder {
    pub(crate) file_name: ::std::option::Option<::std::string::String>,
    pub(crate) folder_path: ::std::option::Option<::std::string::String>,
}
impl FileBatchJobIdentifierBuilder {
    /// <p>The file name for the batch job identifier.</p>
    /// This field is required.
    pub fn file_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The file name for the batch job identifier.</p>
    pub fn set_file_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_name = input;
        self
    }
    /// <p>The file name for the batch job identifier.</p>
    pub fn get_file_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_name
    }
    /// <p>The relative path to the file name for the batch job identifier.</p>
    pub fn folder_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.folder_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The relative path to the file name for the batch job identifier.</p>
    pub fn set_folder_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.folder_path = input;
        self
    }
    /// <p>The relative path to the file name for the batch job identifier.</p>
    pub fn get_folder_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.folder_path
    }
    /// Consumes the builder and constructs a [`FileBatchJobIdentifier`](crate::types::FileBatchJobIdentifier).
    /// This method will fail if any of the following fields are not set:
    /// - [`file_name`](crate::types::builders::FileBatchJobIdentifierBuilder::file_name)
    pub fn build(self) -> ::std::result::Result<crate::types::FileBatchJobIdentifier, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FileBatchJobIdentifier {
            file_name: self.file_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "file_name",
                    "file_name was not specified but it is required when building FileBatchJobIdentifier",
                )
            })?,
            folder_path: self.folder_path,
        })
    }
}
