// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the location for the file that's being processed.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InputFileLocation {
    /// <p>Specifies the details for the Amazon S3 file that's being copied or decrypted.</p>
    pub s3_file_location: ::std::option::Option<crate::types::S3InputFileLocation>,
    /// <p>Specifies the details for the Amazon Elastic File System (Amazon EFS) file that's being decrypted.</p>
    pub efs_file_location: ::std::option::Option<crate::types::EfsFileLocation>,
}
impl InputFileLocation {
    /// <p>Specifies the details for the Amazon S3 file that's being copied or decrypted.</p>
    pub fn s3_file_location(&self) -> ::std::option::Option<&crate::types::S3InputFileLocation> {
        self.s3_file_location.as_ref()
    }
    /// <p>Specifies the details for the Amazon Elastic File System (Amazon EFS) file that's being decrypted.</p>
    pub fn efs_file_location(&self) -> ::std::option::Option<&crate::types::EfsFileLocation> {
        self.efs_file_location.as_ref()
    }
}
impl InputFileLocation {
    /// Creates a new builder-style object to manufacture [`InputFileLocation`](crate::types::InputFileLocation).
    pub fn builder() -> crate::types::builders::InputFileLocationBuilder {
        crate::types::builders::InputFileLocationBuilder::default()
    }
}

/// A builder for [`InputFileLocation`](crate::types::InputFileLocation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InputFileLocationBuilder {
    pub(crate) s3_file_location: ::std::option::Option<crate::types::S3InputFileLocation>,
    pub(crate) efs_file_location: ::std::option::Option<crate::types::EfsFileLocation>,
}
impl InputFileLocationBuilder {
    /// <p>Specifies the details for the Amazon S3 file that's being copied or decrypted.</p>
    pub fn s3_file_location(mut self, input: crate::types::S3InputFileLocation) -> Self {
        self.s3_file_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the details for the Amazon S3 file that's being copied or decrypted.</p>
    pub fn set_s3_file_location(mut self, input: ::std::option::Option<crate::types::S3InputFileLocation>) -> Self {
        self.s3_file_location = input;
        self
    }
    /// <p>Specifies the details for the Amazon S3 file that's being copied or decrypted.</p>
    pub fn get_s3_file_location(&self) -> &::std::option::Option<crate::types::S3InputFileLocation> {
        &self.s3_file_location
    }
    /// <p>Specifies the details for the Amazon Elastic File System (Amazon EFS) file that's being decrypted.</p>
    pub fn efs_file_location(mut self, input: crate::types::EfsFileLocation) -> Self {
        self.efs_file_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the details for the Amazon Elastic File System (Amazon EFS) file that's being decrypted.</p>
    pub fn set_efs_file_location(mut self, input: ::std::option::Option<crate::types::EfsFileLocation>) -> Self {
        self.efs_file_location = input;
        self
    }
    /// <p>Specifies the details for the Amazon Elastic File System (Amazon EFS) file that's being decrypted.</p>
    pub fn get_efs_file_location(&self) -> &::std::option::Option<crate::types::EfsFileLocation> {
        &self.efs_file_location
    }
    /// Consumes the builder and constructs a [`InputFileLocation`](crate::types::InputFileLocation).
    pub fn build(self) -> crate::types::InputFileLocation {
        crate::types::InputFileLocation {
            s3_file_location: self.s3_file_location,
            efs_file_location: self.efs_file_location,
        }
    }
}
