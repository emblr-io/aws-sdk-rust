// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartDicomImportJobInput {
    /// <p>The import job name.</p>
    pub job_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants permission to access medical imaging resources.</p>
    pub data_access_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for API idempotency.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The data store identifier.</p>
    pub datastore_id: ::std::option::Option<::std::string::String>,
    /// <p>The input prefix path for the S3 bucket that contains the DICOM files to be imported.</p>
    pub input_s3_uri: ::std::option::Option<::std::string::String>,
    /// <p>The output prefix of the S3 bucket to upload the results of the DICOM import job.</p>
    pub output_s3_uri: ::std::option::Option<::std::string::String>,
    /// <p>The account ID of the source S3 bucket owner.</p>
    pub input_owner_account_id: ::std::option::Option<::std::string::String>,
}
impl StartDicomImportJobInput {
    /// <p>The import job name.</p>
    pub fn job_name(&self) -> ::std::option::Option<&str> {
        self.job_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants permission to access medical imaging resources.</p>
    pub fn data_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.data_access_role_arn.as_deref()
    }
    /// <p>A unique identifier for API idempotency.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The data store identifier.</p>
    pub fn datastore_id(&self) -> ::std::option::Option<&str> {
        self.datastore_id.as_deref()
    }
    /// <p>The input prefix path for the S3 bucket that contains the DICOM files to be imported.</p>
    pub fn input_s3_uri(&self) -> ::std::option::Option<&str> {
        self.input_s3_uri.as_deref()
    }
    /// <p>The output prefix of the S3 bucket to upload the results of the DICOM import job.</p>
    pub fn output_s3_uri(&self) -> ::std::option::Option<&str> {
        self.output_s3_uri.as_deref()
    }
    /// <p>The account ID of the source S3 bucket owner.</p>
    pub fn input_owner_account_id(&self) -> ::std::option::Option<&str> {
        self.input_owner_account_id.as_deref()
    }
}
impl StartDicomImportJobInput {
    /// Creates a new builder-style object to manufacture [`StartDicomImportJobInput`](crate::operation::start_dicom_import_job::StartDicomImportJobInput).
    pub fn builder() -> crate::operation::start_dicom_import_job::builders::StartDicomImportJobInputBuilder {
        crate::operation::start_dicom_import_job::builders::StartDicomImportJobInputBuilder::default()
    }
}

/// A builder for [`StartDicomImportJobInput`](crate::operation::start_dicom_import_job::StartDicomImportJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartDicomImportJobInputBuilder {
    pub(crate) job_name: ::std::option::Option<::std::string::String>,
    pub(crate) data_access_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) datastore_id: ::std::option::Option<::std::string::String>,
    pub(crate) input_s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) output_s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) input_owner_account_id: ::std::option::Option<::std::string::String>,
}
impl StartDicomImportJobInputBuilder {
    /// <p>The import job name.</p>
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
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants permission to access medical imaging resources.</p>
    /// This field is required.
    pub fn data_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants permission to access medical imaging resources.</p>
    pub fn set_data_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_access_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that grants permission to access medical imaging resources.</p>
    pub fn get_data_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_access_role_arn
    }
    /// <p>A unique identifier for API idempotency.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for API idempotency.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique identifier for API idempotency.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
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
    /// <p>The input prefix path for the S3 bucket that contains the DICOM files to be imported.</p>
    /// This field is required.
    pub fn input_s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The input prefix path for the S3 bucket that contains the DICOM files to be imported.</p>
    pub fn set_input_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_s3_uri = input;
        self
    }
    /// <p>The input prefix path for the S3 bucket that contains the DICOM files to be imported.</p>
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
    /// <p>The account ID of the source S3 bucket owner.</p>
    pub fn input_owner_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_owner_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID of the source S3 bucket owner.</p>
    pub fn set_input_owner_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_owner_account_id = input;
        self
    }
    /// <p>The account ID of the source S3 bucket owner.</p>
    pub fn get_input_owner_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_owner_account_id
    }
    /// Consumes the builder and constructs a [`StartDicomImportJobInput`](crate::operation::start_dicom_import_job::StartDicomImportJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_dicom_import_job::StartDicomImportJobInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_dicom_import_job::StartDicomImportJobInput {
            job_name: self.job_name,
            data_access_role_arn: self.data_access_role_arn,
            client_token: self.client_token,
            datastore_id: self.datastore_id,
            input_s3_uri: self.input_s3_uri,
            output_s3_uri: self.output_s3_uri,
            input_owner_account_id: self.input_owner_account_id,
        })
    }
}
