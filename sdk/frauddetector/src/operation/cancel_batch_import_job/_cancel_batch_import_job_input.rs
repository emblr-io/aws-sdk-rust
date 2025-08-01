// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelBatchImportJobInput {
    /// <p>The ID of an in-progress batch import job to cancel.</p>
    /// <p>Amazon Fraud Detector will throw an error if the batch import job is in <code>FAILED</code>, <code>CANCELED</code>, or <code>COMPLETED</code> state.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
}
impl CancelBatchImportJobInput {
    /// <p>The ID of an in-progress batch import job to cancel.</p>
    /// <p>Amazon Fraud Detector will throw an error if the batch import job is in <code>FAILED</code>, <code>CANCELED</code>, or <code>COMPLETED</code> state.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
}
impl CancelBatchImportJobInput {
    /// Creates a new builder-style object to manufacture [`CancelBatchImportJobInput`](crate::operation::cancel_batch_import_job::CancelBatchImportJobInput).
    pub fn builder() -> crate::operation::cancel_batch_import_job::builders::CancelBatchImportJobInputBuilder {
        crate::operation::cancel_batch_import_job::builders::CancelBatchImportJobInputBuilder::default()
    }
}

/// A builder for [`CancelBatchImportJobInput`](crate::operation::cancel_batch_import_job::CancelBatchImportJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelBatchImportJobInputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
}
impl CancelBatchImportJobInputBuilder {
    /// <p>The ID of an in-progress batch import job to cancel.</p>
    /// <p>Amazon Fraud Detector will throw an error if the batch import job is in <code>FAILED</code>, <code>CANCELED</code>, or <code>COMPLETED</code> state.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of an in-progress batch import job to cancel.</p>
    /// <p>Amazon Fraud Detector will throw an error if the batch import job is in <code>FAILED</code>, <code>CANCELED</code>, or <code>COMPLETED</code> state.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The ID of an in-progress batch import job to cancel.</p>
    /// <p>Amazon Fraud Detector will throw an error if the batch import job is in <code>FAILED</code>, <code>CANCELED</code>, or <code>COMPLETED</code> state.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// Consumes the builder and constructs a [`CancelBatchImportJobInput`](crate::operation::cancel_batch_import_job::CancelBatchImportJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_batch_import_job::CancelBatchImportJobInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::cancel_batch_import_job::CancelBatchImportJobInput { job_id: self.job_id })
    }
}
