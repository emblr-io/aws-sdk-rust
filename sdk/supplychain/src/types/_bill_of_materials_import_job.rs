// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The BillOfMaterialsImportJob details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BillOfMaterialsImportJob {
    /// <p>The BillOfMaterialsImportJob instanceId.</p>
    pub instance_id: ::std::string::String,
    /// <p>The BillOfMaterialsImportJob jobId.</p>
    pub job_id: ::std::string::String,
    /// <p>The BillOfMaterialsImportJob ConfigurationJobStatus.</p>
    pub status: crate::types::ConfigurationJobStatus,
    /// <p>The S3 URI from which the CSV is read.</p>
    pub s3_uri: ::std::string::String,
    /// <p>When the BillOfMaterialsImportJob has reached a terminal state, there will be a message.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl BillOfMaterialsImportJob {
    /// <p>The BillOfMaterialsImportJob instanceId.</p>
    pub fn instance_id(&self) -> &str {
        use std::ops::Deref;
        self.instance_id.deref()
    }
    /// <p>The BillOfMaterialsImportJob jobId.</p>
    pub fn job_id(&self) -> &str {
        use std::ops::Deref;
        self.job_id.deref()
    }
    /// <p>The BillOfMaterialsImportJob ConfigurationJobStatus.</p>
    pub fn status(&self) -> &crate::types::ConfigurationJobStatus {
        &self.status
    }
    /// <p>The S3 URI from which the CSV is read.</p>
    pub fn s3_uri(&self) -> &str {
        use std::ops::Deref;
        self.s3_uri.deref()
    }
    /// <p>When the BillOfMaterialsImportJob has reached a terminal state, there will be a message.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl BillOfMaterialsImportJob {
    /// Creates a new builder-style object to manufacture [`BillOfMaterialsImportJob`](crate::types::BillOfMaterialsImportJob).
    pub fn builder() -> crate::types::builders::BillOfMaterialsImportJobBuilder {
        crate::types::builders::BillOfMaterialsImportJobBuilder::default()
    }
}

/// A builder for [`BillOfMaterialsImportJob`](crate::types::BillOfMaterialsImportJob).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BillOfMaterialsImportJobBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ConfigurationJobStatus>,
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl BillOfMaterialsImportJobBuilder {
    /// <p>The BillOfMaterialsImportJob instanceId.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The BillOfMaterialsImportJob instanceId.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The BillOfMaterialsImportJob instanceId.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The BillOfMaterialsImportJob jobId.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The BillOfMaterialsImportJob jobId.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The BillOfMaterialsImportJob jobId.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The BillOfMaterialsImportJob ConfigurationJobStatus.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::ConfigurationJobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The BillOfMaterialsImportJob ConfigurationJobStatus.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ConfigurationJobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The BillOfMaterialsImportJob ConfigurationJobStatus.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ConfigurationJobStatus> {
        &self.status
    }
    /// <p>The S3 URI from which the CSV is read.</p>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3 URI from which the CSV is read.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>The S3 URI from which the CSV is read.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// <p>When the BillOfMaterialsImportJob has reached a terminal state, there will be a message.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the BillOfMaterialsImportJob has reached a terminal state, there will be a message.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>When the BillOfMaterialsImportJob has reached a terminal state, there will be a message.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`BillOfMaterialsImportJob`](crate::types::BillOfMaterialsImportJob).
    /// This method will fail if any of the following fields are not set:
    /// - [`instance_id`](crate::types::builders::BillOfMaterialsImportJobBuilder::instance_id)
    /// - [`job_id`](crate::types::builders::BillOfMaterialsImportJobBuilder::job_id)
    /// - [`status`](crate::types::builders::BillOfMaterialsImportJobBuilder::status)
    /// - [`s3_uri`](crate::types::builders::BillOfMaterialsImportJobBuilder::s3_uri)
    pub fn build(self) -> ::std::result::Result<crate::types::BillOfMaterialsImportJob, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BillOfMaterialsImportJob {
            instance_id: self.instance_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "instance_id",
                    "instance_id was not specified but it is required when building BillOfMaterialsImportJob",
                )
            })?,
            job_id: self.job_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_id",
                    "job_id was not specified but it is required when building BillOfMaterialsImportJob",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building BillOfMaterialsImportJob",
                )
            })?,
            s3_uri: self.s3_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_uri",
                    "s3_uri was not specified but it is required when building BillOfMaterialsImportJob",
                )
            })?,
            message: self.message,
        })
    }
}
