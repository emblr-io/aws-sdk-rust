// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Properties of the import job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DicomImportJobProperties {
    /// <p>The import job identifier.</p>
    pub job_id: ::std::string::String,
    /// <p>The import job name.</p>
    pub job_name: ::std::string::String,
    /// <p>The filters for listing import jobs based on status.</p>
    pub job_status: crate::types::JobStatus,
    /// <p>The data store identifier.</p>
    pub datastore_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) that grants permissions to access medical imaging resources.</p>
    pub data_access_role_arn: ::std::string::String,
    /// <p>The timestamp for when the import job was ended.</p>
    pub ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp for when the import job was submitted.</p>
    pub submitted_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The input prefix path for the S3 bucket that contains the DICOM P10 files to be imported.</p>
    pub input_s3_uri: ::std::string::String,
    /// <p>The output prefix of the S3 bucket to upload the results of the DICOM import job.</p>
    pub output_s3_uri: ::std::string::String,
    /// <p>The error message thrown if an import job fails.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl DicomImportJobProperties {
    /// <p>The import job identifier.</p>
    pub fn job_id(&self) -> &str {
        use std::ops::Deref;
        self.job_id.deref()
    }
    /// <p>The import job name.</p>
    pub fn job_name(&self) -> &str {
        use std::ops::Deref;
        self.job_name.deref()
    }
    /// <p>The filters for listing import jobs based on status.</p>
    pub fn job_status(&self) -> &crate::types::JobStatus {
        &self.job_status
    }
    /// <p>The data store identifier.</p>
    pub fn datastore_id(&self) -> &str {
        use std::ops::Deref;
        self.datastore_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) that grants permissions to access medical imaging resources.</p>
    pub fn data_access_role_arn(&self) -> &str {
        use std::ops::Deref;
        self.data_access_role_arn.deref()
    }
    /// <p>The timestamp for when the import job was ended.</p>
    pub fn ended_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.ended_at.as_ref()
    }
    /// <p>The timestamp for when the import job was submitted.</p>
    pub fn submitted_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.submitted_at.as_ref()
    }
    /// <p>The input prefix path for the S3 bucket that contains the DICOM P10 files to be imported.</p>
    pub fn input_s3_uri(&self) -> &str {
        use std::ops::Deref;
        self.input_s3_uri.deref()
    }
    /// <p>The output prefix of the S3 bucket to upload the results of the DICOM import job.</p>
    pub fn output_s3_uri(&self) -> &str {
        use std::ops::Deref;
        self.output_s3_uri.deref()
    }
    /// <p>The error message thrown if an import job fails.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl DicomImportJobProperties {
    /// Creates a new builder-style object to manufacture [`DicomImportJobProperties`](crate::types::DicomImportJobProperties).
    pub fn builder() -> crate::types::builders::DicomImportJobPropertiesBuilder {
        crate::types::builders::DicomImportJobPropertiesBuilder::default()
    }
}

/// A builder for [`DicomImportJobProperties`](crate::types::DicomImportJobProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DicomImportJobPropertiesBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_name: ::std::option::Option<::std::string::String>,
    pub(crate) job_status: ::std::option::Option<crate::types::JobStatus>,
    pub(crate) datastore_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_access_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) submitted_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) input_s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) output_s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl DicomImportJobPropertiesBuilder {
    /// <p>The import job identifier.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The import job identifier.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The import job identifier.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The import job name.</p>
    /// This field is required.
    pub fn job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The import job name.</p>
    pub fn set_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_name = input;
        self
    }
    /// <p>The import job name.</p>
    pub fn get_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_name
    }
    /// <p>The filters for listing import jobs based on status.</p>
    /// This field is required.
    pub fn job_status(mut self, input: crate::types::JobStatus) -> Self {
        self.job_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The filters for listing import jobs based on status.</p>
    pub fn set_job_status(mut self, input: ::std::option::Option<crate::types::JobStatus>) -> Self {
        self.job_status = input;
        self
    }
    /// <p>The filters for listing import jobs based on status.</p>
    pub fn get_job_status(&self) -> &::std::option::Option<crate::types::JobStatus> {
        &self.job_status
    }
    /// <p>The data store identifier.</p>
    /// This field is required.
    pub fn datastore_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.datastore_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The data store identifier.</p>
    pub fn set_datastore_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.datastore_id = input;
        self
    }
    /// <p>The data store identifier.</p>
    pub fn get_datastore_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.datastore_id
    }
    /// <p>The Amazon Resource Name (ARN) that grants permissions to access medical imaging resources.</p>
    /// This field is required.
    pub fn data_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that grants permissions to access medical imaging resources.</p>
    pub fn set_data_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_access_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that grants permissions to access medical imaging resources.</p>
    pub fn get_data_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_access_role_arn
    }
    /// <p>The timestamp for when the import job was ended.</p>
    pub fn ended_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.ended_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the import job was ended.</p>
    pub fn set_ended_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.ended_at = input;
        self
    }
    /// <p>The timestamp for when the import job was ended.</p>
    pub fn get_ended_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.ended_at
    }
    /// <p>The timestamp for when the import job was submitted.</p>
    pub fn submitted_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.submitted_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the import job was submitted.</p>
    pub fn set_submitted_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.submitted_at = input;
        self
    }
    /// <p>The timestamp for when the import job was submitted.</p>
    pub fn get_submitted_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.submitted_at
    }
    /// <p>The input prefix path for the S3 bucket that contains the DICOM P10 files to be imported.</p>
    /// This field is required.
    pub fn input_s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The input prefix path for the S3 bucket that contains the DICOM P10 files to be imported.</p>
    pub fn set_input_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_s3_uri = input;
        self
    }
    /// <p>The input prefix path for the S3 bucket that contains the DICOM P10 files to be imported.</p>
    pub fn get_input_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_s3_uri
    }
    /// <p>The output prefix of the S3 bucket to upload the results of the DICOM import job.</p>
    /// This field is required.
    pub fn output_s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.output_s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The output prefix of the S3 bucket to upload the results of the DICOM import job.</p>
    pub fn set_output_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.output_s3_uri = input;
        self
    }
    /// <p>The output prefix of the S3 bucket to upload the results of the DICOM import job.</p>
    pub fn get_output_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.output_s3_uri
    }
    /// <p>The error message thrown if an import job fails.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message thrown if an import job fails.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The error message thrown if an import job fails.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`DicomImportJobProperties`](crate::types::DicomImportJobProperties).
    /// This method will fail if any of the following fields are not set:
    /// - [`job_id`](crate::types::builders::DicomImportJobPropertiesBuilder::job_id)
    /// - [`job_name`](crate::types::builders::DicomImportJobPropertiesBuilder::job_name)
    /// - [`job_status`](crate::types::builders::DicomImportJobPropertiesBuilder::job_status)
    /// - [`datastore_id`](crate::types::builders::DicomImportJobPropertiesBuilder::datastore_id)
    /// - [`data_access_role_arn`](crate::types::builders::DicomImportJobPropertiesBuilder::data_access_role_arn)
    /// - [`input_s3_uri`](crate::types::builders::DicomImportJobPropertiesBuilder::input_s3_uri)
    /// - [`output_s3_uri`](crate::types::builders::DicomImportJobPropertiesBuilder::output_s3_uri)
    pub fn build(self) -> ::std::result::Result<crate::types::DicomImportJobProperties, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DicomImportJobProperties {
            job_id: self.job_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_id",
                    "job_id was not specified but it is required when building DicomImportJobProperties",
                )
            })?,
            job_name: self.job_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_name",
                    "job_name was not specified but it is required when building DicomImportJobProperties",
                )
            })?,
            job_status: self.job_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_status",
                    "job_status was not specified but it is required when building DicomImportJobProperties",
                )
            })?,
            datastore_id: self.datastore_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "datastore_id",
                    "datastore_id was not specified but it is required when building DicomImportJobProperties",
                )
            })?,
            data_access_role_arn: self.data_access_role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_access_role_arn",
                    "data_access_role_arn was not specified but it is required when building DicomImportJobProperties",
                )
            })?,
            ended_at: self.ended_at,
            submitted_at: self.submitted_at,
            input_s3_uri: self.input_s3_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "input_s3_uri",
                    "input_s3_uri was not specified but it is required when building DicomImportJobProperties",
                )
            })?,
            output_s3_uri: self.output_s3_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "output_s3_uri",
                    "output_s3_uri was not specified but it is required when building DicomImportJobProperties",
                )
            })?,
            message: self.message,
        })
    }
}
