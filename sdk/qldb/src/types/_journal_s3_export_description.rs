// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a journal export job, including the ledger name, export ID, creation time, current status, and the parameters of the original export creation request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JournalS3ExportDescription {
    /// <p>The name of the ledger.</p>
    pub ledger_name: ::std::string::String,
    /// <p>The UUID (represented in Base62-encoded text) of the journal export job.</p>
    pub export_id: ::std::string::String,
    /// <p>The date and time, in epoch time format, when the export job was created. (Epoch time format is the number of seconds elapsed since 12:00:00 AM January 1, 1970 UTC.)</p>
    pub export_creation_time: ::aws_smithy_types::DateTime,
    /// <p>The current state of the journal export job.</p>
    pub status: crate::types::ExportStatus,
    /// <p>The inclusive start date and time for the range of journal contents that was specified in the original export request.</p>
    pub inclusive_start_time: ::aws_smithy_types::DateTime,
    /// <p>The exclusive end date and time for the range of journal contents that was specified in the original export request.</p>
    pub exclusive_end_time: ::aws_smithy_types::DateTime,
    /// <p>The Amazon Simple Storage Service (Amazon S3) bucket location in which a journal export job writes the journal contents.</p>
    pub s3_export_configuration: ::std::option::Option<crate::types::S3ExportConfiguration>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants QLDB permissions for a journal export job to do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Write objects into your Amazon Simple Storage Service (Amazon S3) bucket.</p></li>
    /// <li>
    /// <p>(Optional) Use your customer managed key in Key Management Service (KMS) for server-side encryption of your exported data.</p></li>
    /// </ul>
    pub role_arn: ::std::string::String,
    /// <p>The output format of the exported journal data.</p>
    pub output_format: ::std::option::Option<crate::types::OutputFormat>,
}
impl JournalS3ExportDescription {
    /// <p>The name of the ledger.</p>
    pub fn ledger_name(&self) -> &str {
        use std::ops::Deref;
        self.ledger_name.deref()
    }
    /// <p>The UUID (represented in Base62-encoded text) of the journal export job.</p>
    pub fn export_id(&self) -> &str {
        use std::ops::Deref;
        self.export_id.deref()
    }
    /// <p>The date and time, in epoch time format, when the export job was created. (Epoch time format is the number of seconds elapsed since 12:00:00 AM January 1, 1970 UTC.)</p>
    pub fn export_creation_time(&self) -> &::aws_smithy_types::DateTime {
        &self.export_creation_time
    }
    /// <p>The current state of the journal export job.</p>
    pub fn status(&self) -> &crate::types::ExportStatus {
        &self.status
    }
    /// <p>The inclusive start date and time for the range of journal contents that was specified in the original export request.</p>
    pub fn inclusive_start_time(&self) -> &::aws_smithy_types::DateTime {
        &self.inclusive_start_time
    }
    /// <p>The exclusive end date and time for the range of journal contents that was specified in the original export request.</p>
    pub fn exclusive_end_time(&self) -> &::aws_smithy_types::DateTime {
        &self.exclusive_end_time
    }
    /// <p>The Amazon Simple Storage Service (Amazon S3) bucket location in which a journal export job writes the journal contents.</p>
    pub fn s3_export_configuration(&self) -> ::std::option::Option<&crate::types::S3ExportConfiguration> {
        self.s3_export_configuration.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants QLDB permissions for a journal export job to do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Write objects into your Amazon Simple Storage Service (Amazon S3) bucket.</p></li>
    /// <li>
    /// <p>(Optional) Use your customer managed key in Key Management Service (KMS) for server-side encryption of your exported data.</p></li>
    /// </ul>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
    /// <p>The output format of the exported journal data.</p>
    pub fn output_format(&self) -> ::std::option::Option<&crate::types::OutputFormat> {
        self.output_format.as_ref()
    }
}
impl JournalS3ExportDescription {
    /// Creates a new builder-style object to manufacture [`JournalS3ExportDescription`](crate::types::JournalS3ExportDescription).
    pub fn builder() -> crate::types::builders::JournalS3ExportDescriptionBuilder {
        crate::types::builders::JournalS3ExportDescriptionBuilder::default()
    }
}

/// A builder for [`JournalS3ExportDescription`](crate::types::JournalS3ExportDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JournalS3ExportDescriptionBuilder {
    pub(crate) ledger_name: ::std::option::Option<::std::string::String>,
    pub(crate) export_id: ::std::option::Option<::std::string::String>,
    pub(crate) export_creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::ExportStatus>,
    pub(crate) inclusive_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) exclusive_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) s3_export_configuration: ::std::option::Option<crate::types::S3ExportConfiguration>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) output_format: ::std::option::Option<crate::types::OutputFormat>,
}
impl JournalS3ExportDescriptionBuilder {
    /// <p>The name of the ledger.</p>
    /// This field is required.
    pub fn ledger_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ledger_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the ledger.</p>
    pub fn set_ledger_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ledger_name = input;
        self
    }
    /// <p>The name of the ledger.</p>
    pub fn get_ledger_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.ledger_name
    }
    /// <p>The UUID (represented in Base62-encoded text) of the journal export job.</p>
    /// This field is required.
    pub fn export_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.export_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The UUID (represented in Base62-encoded text) of the journal export job.</p>
    pub fn set_export_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.export_id = input;
        self
    }
    /// <p>The UUID (represented in Base62-encoded text) of the journal export job.</p>
    pub fn get_export_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.export_id
    }
    /// <p>The date and time, in epoch time format, when the export job was created. (Epoch time format is the number of seconds elapsed since 12:00:00 AM January 1, 1970 UTC.)</p>
    /// This field is required.
    pub fn export_creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.export_creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in epoch time format, when the export job was created. (Epoch time format is the number of seconds elapsed since 12:00:00 AM January 1, 1970 UTC.)</p>
    pub fn set_export_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.export_creation_time = input;
        self
    }
    /// <p>The date and time, in epoch time format, when the export job was created. (Epoch time format is the number of seconds elapsed since 12:00:00 AM January 1, 1970 UTC.)</p>
    pub fn get_export_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.export_creation_time
    }
    /// <p>The current state of the journal export job.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::ExportStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of the journal export job.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ExportStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current state of the journal export job.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ExportStatus> {
        &self.status
    }
    /// <p>The inclusive start date and time for the range of journal contents that was specified in the original export request.</p>
    /// This field is required.
    pub fn inclusive_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.inclusive_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The inclusive start date and time for the range of journal contents that was specified in the original export request.</p>
    pub fn set_inclusive_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.inclusive_start_time = input;
        self
    }
    /// <p>The inclusive start date and time for the range of journal contents that was specified in the original export request.</p>
    pub fn get_inclusive_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.inclusive_start_time
    }
    /// <p>The exclusive end date and time for the range of journal contents that was specified in the original export request.</p>
    /// This field is required.
    pub fn exclusive_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.exclusive_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The exclusive end date and time for the range of journal contents that was specified in the original export request.</p>
    pub fn set_exclusive_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.exclusive_end_time = input;
        self
    }
    /// <p>The exclusive end date and time for the range of journal contents that was specified in the original export request.</p>
    pub fn get_exclusive_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.exclusive_end_time
    }
    /// <p>The Amazon Simple Storage Service (Amazon S3) bucket location in which a journal export job writes the journal contents.</p>
    /// This field is required.
    pub fn s3_export_configuration(mut self, input: crate::types::S3ExportConfiguration) -> Self {
        self.s3_export_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Simple Storage Service (Amazon S3) bucket location in which a journal export job writes the journal contents.</p>
    pub fn set_s3_export_configuration(mut self, input: ::std::option::Option<crate::types::S3ExportConfiguration>) -> Self {
        self.s3_export_configuration = input;
        self
    }
    /// <p>The Amazon Simple Storage Service (Amazon S3) bucket location in which a journal export job writes the journal contents.</p>
    pub fn get_s3_export_configuration(&self) -> &::std::option::Option<crate::types::S3ExportConfiguration> {
        &self.s3_export_configuration
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants QLDB permissions for a journal export job to do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Write objects into your Amazon Simple Storage Service (Amazon S3) bucket.</p></li>
    /// <li>
    /// <p>(Optional) Use your customer managed key in Key Management Service (KMS) for server-side encryption of your exported data.</p></li>
    /// </ul>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants QLDB permissions for a journal export job to do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Write objects into your Amazon Simple Storage Service (Amazon S3) bucket.</p></li>
    /// <li>
    /// <p>(Optional) Use your customer managed key in Key Management Service (KMS) for server-side encryption of your exported data.</p></li>
    /// </ul>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants QLDB permissions for a journal export job to do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Write objects into your Amazon Simple Storage Service (Amazon S3) bucket.</p></li>
    /// <li>
    /// <p>(Optional) Use your customer managed key in Key Management Service (KMS) for server-side encryption of your exported data.</p></li>
    /// </ul>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The output format of the exported journal data.</p>
    pub fn output_format(mut self, input: crate::types::OutputFormat) -> Self {
        self.output_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The output format of the exported journal data.</p>
    pub fn set_output_format(mut self, input: ::std::option::Option<crate::types::OutputFormat>) -> Self {
        self.output_format = input;
        self
    }
    /// <p>The output format of the exported journal data.</p>
    pub fn get_output_format(&self) -> &::std::option::Option<crate::types::OutputFormat> {
        &self.output_format
    }
    /// Consumes the builder and constructs a [`JournalS3ExportDescription`](crate::types::JournalS3ExportDescription).
    /// This method will fail if any of the following fields are not set:
    /// - [`ledger_name`](crate::types::builders::JournalS3ExportDescriptionBuilder::ledger_name)
    /// - [`export_id`](crate::types::builders::JournalS3ExportDescriptionBuilder::export_id)
    /// - [`export_creation_time`](crate::types::builders::JournalS3ExportDescriptionBuilder::export_creation_time)
    /// - [`status`](crate::types::builders::JournalS3ExportDescriptionBuilder::status)
    /// - [`inclusive_start_time`](crate::types::builders::JournalS3ExportDescriptionBuilder::inclusive_start_time)
    /// - [`exclusive_end_time`](crate::types::builders::JournalS3ExportDescriptionBuilder::exclusive_end_time)
    /// - [`role_arn`](crate::types::builders::JournalS3ExportDescriptionBuilder::role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::JournalS3ExportDescription, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::JournalS3ExportDescription {
            ledger_name: self.ledger_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ledger_name",
                    "ledger_name was not specified but it is required when building JournalS3ExportDescription",
                )
            })?,
            export_id: self.export_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "export_id",
                    "export_id was not specified but it is required when building JournalS3ExportDescription",
                )
            })?,
            export_creation_time: self.export_creation_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "export_creation_time",
                    "export_creation_time was not specified but it is required when building JournalS3ExportDescription",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building JournalS3ExportDescription",
                )
            })?,
            inclusive_start_time: self.inclusive_start_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "inclusive_start_time",
                    "inclusive_start_time was not specified but it is required when building JournalS3ExportDescription",
                )
            })?,
            exclusive_end_time: self.exclusive_end_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "exclusive_end_time",
                    "exclusive_end_time was not specified but it is required when building JournalS3ExportDescription",
                )
            })?,
            s3_export_configuration: self.s3_export_configuration,
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building JournalS3ExportDescription",
                )
            })?,
            output_format: self.output_format,
        })
    }
}
