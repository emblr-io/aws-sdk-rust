// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details of the operation to be performed by the job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoExportRevisionToS3RequestDetails {
    /// <p>Encryption configuration for the auto export job.</p>
    pub encryption: ::std::option::Option<crate::types::ExportServerSideEncryption>,
    /// <p>A revision destination is the Amazon S3 bucket folder destination to where the export will be sent.</p>
    pub revision_destination: ::std::option::Option<crate::types::AutoExportRevisionDestinationEntry>,
}
impl AutoExportRevisionToS3RequestDetails {
    /// <p>Encryption configuration for the auto export job.</p>
    pub fn encryption(&self) -> ::std::option::Option<&crate::types::ExportServerSideEncryption> {
        self.encryption.as_ref()
    }
    /// <p>A revision destination is the Amazon S3 bucket folder destination to where the export will be sent.</p>
    pub fn revision_destination(&self) -> ::std::option::Option<&crate::types::AutoExportRevisionDestinationEntry> {
        self.revision_destination.as_ref()
    }
}
impl AutoExportRevisionToS3RequestDetails {
    /// Creates a new builder-style object to manufacture [`AutoExportRevisionToS3RequestDetails`](crate::types::AutoExportRevisionToS3RequestDetails).
    pub fn builder() -> crate::types::builders::AutoExportRevisionToS3RequestDetailsBuilder {
        crate::types::builders::AutoExportRevisionToS3RequestDetailsBuilder::default()
    }
}

/// A builder for [`AutoExportRevisionToS3RequestDetails`](crate::types::AutoExportRevisionToS3RequestDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoExportRevisionToS3RequestDetailsBuilder {
    pub(crate) encryption: ::std::option::Option<crate::types::ExportServerSideEncryption>,
    pub(crate) revision_destination: ::std::option::Option<crate::types::AutoExportRevisionDestinationEntry>,
}
impl AutoExportRevisionToS3RequestDetailsBuilder {
    /// <p>Encryption configuration for the auto export job.</p>
    pub fn encryption(mut self, input: crate::types::ExportServerSideEncryption) -> Self {
        self.encryption = ::std::option::Option::Some(input);
        self
    }
    /// <p>Encryption configuration for the auto export job.</p>
    pub fn set_encryption(mut self, input: ::std::option::Option<crate::types::ExportServerSideEncryption>) -> Self {
        self.encryption = input;
        self
    }
    /// <p>Encryption configuration for the auto export job.</p>
    pub fn get_encryption(&self) -> &::std::option::Option<crate::types::ExportServerSideEncryption> {
        &self.encryption
    }
    /// <p>A revision destination is the Amazon S3 bucket folder destination to where the export will be sent.</p>
    /// This field is required.
    pub fn revision_destination(mut self, input: crate::types::AutoExportRevisionDestinationEntry) -> Self {
        self.revision_destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>A revision destination is the Amazon S3 bucket folder destination to where the export will be sent.</p>
    pub fn set_revision_destination(mut self, input: ::std::option::Option<crate::types::AutoExportRevisionDestinationEntry>) -> Self {
        self.revision_destination = input;
        self
    }
    /// <p>A revision destination is the Amazon S3 bucket folder destination to where the export will be sent.</p>
    pub fn get_revision_destination(&self) -> &::std::option::Option<crate::types::AutoExportRevisionDestinationEntry> {
        &self.revision_destination
    }
    /// Consumes the builder and constructs a [`AutoExportRevisionToS3RequestDetails`](crate::types::AutoExportRevisionToS3RequestDetails).
    pub fn build(self) -> crate::types::AutoExportRevisionToS3RequestDetails {
        crate::types::AutoExportRevisionToS3RequestDetails {
            encryption: self.encryption,
            revision_destination: self.revision_destination,
        }
    }
}
