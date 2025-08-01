// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about an imported variant item.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VariantImportItemDetail {
    /// <p>The source file's location in Amazon S3.</p>
    pub source: ::std::string::String,
    /// <p>The item's job status.</p>
    pub job_status: crate::types::JobStatus,
    /// <p>A message that provides additional context about a job</p>
    pub status_message: ::std::option::Option<::std::string::String>,
}
impl VariantImportItemDetail {
    /// <p>The source file's location in Amazon S3.</p>
    pub fn source(&self) -> &str {
        use std::ops::Deref;
        self.source.deref()
    }
    /// <p>The item's job status.</p>
    pub fn job_status(&self) -> &crate::types::JobStatus {
        &self.job_status
    }
    /// <p>A message that provides additional context about a job</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
}
impl VariantImportItemDetail {
    /// Creates a new builder-style object to manufacture [`VariantImportItemDetail`](crate::types::VariantImportItemDetail).
    pub fn builder() -> crate::types::builders::VariantImportItemDetailBuilder {
        crate::types::builders::VariantImportItemDetailBuilder::default()
    }
}

/// A builder for [`VariantImportItemDetail`](crate::types::VariantImportItemDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VariantImportItemDetailBuilder {
    pub(crate) source: ::std::option::Option<::std::string::String>,
    pub(crate) job_status: ::std::option::Option<crate::types::JobStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
}
impl VariantImportItemDetailBuilder {
    /// <p>The source file's location in Amazon S3.</p>
    /// This field is required.
    pub fn source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source file's location in Amazon S3.</p>
    pub fn set_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source = input;
        self
    }
    /// <p>The source file's location in Amazon S3.</p>
    pub fn get_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.source
    }
    /// <p>The item's job status.</p>
    /// This field is required.
    pub fn job_status(mut self, input: crate::types::JobStatus) -> Self {
        self.job_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The item's job status.</p>
    pub fn set_job_status(mut self, input: ::std::option::Option<crate::types::JobStatus>) -> Self {
        self.job_status = input;
        self
    }
    /// <p>The item's job status.</p>
    pub fn get_job_status(&self) -> &::std::option::Option<crate::types::JobStatus> {
        &self.job_status
    }
    /// <p>A message that provides additional context about a job</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message that provides additional context about a job</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>A message that provides additional context about a job</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// Consumes the builder and constructs a [`VariantImportItemDetail`](crate::types::VariantImportItemDetail).
    /// This method will fail if any of the following fields are not set:
    /// - [`source`](crate::types::builders::VariantImportItemDetailBuilder::source)
    /// - [`job_status`](crate::types::builders::VariantImportItemDetailBuilder::job_status)
    pub fn build(self) -> ::std::result::Result<crate::types::VariantImportItemDetail, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VariantImportItemDetail {
            source: self.source.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source",
                    "source was not specified but it is required when building VariantImportItemDetail",
                )
            })?,
            job_status: self.job_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_status",
                    "job_status was not specified but it is required when building VariantImportItemDetail",
                )
            })?,
            status_message: self.status_message,
        })
    }
}
