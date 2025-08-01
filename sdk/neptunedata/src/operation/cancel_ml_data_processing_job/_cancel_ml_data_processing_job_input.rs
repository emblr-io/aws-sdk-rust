// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelMlDataProcessingJobInput {
    /// <p>The unique identifier of the data-processing job.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of an IAM role that provides Neptune access to SageMaker and Amazon S3 resources. This must be listed in your DB cluster parameter group or an error will occur.</p>
    pub neptune_iam_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>If set to <code>TRUE</code>, this flag specifies that all Neptune ML S3 artifacts should be deleted when the job is stopped. The default is <code>FALSE</code>.</p>
    pub clean: ::std::option::Option<bool>,
}
impl CancelMlDataProcessingJobInput {
    /// <p>The unique identifier of the data-processing job.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The ARN of an IAM role that provides Neptune access to SageMaker and Amazon S3 resources. This must be listed in your DB cluster parameter group or an error will occur.</p>
    pub fn neptune_iam_role_arn(&self) -> ::std::option::Option<&str> {
        self.neptune_iam_role_arn.as_deref()
    }
    /// <p>If set to <code>TRUE</code>, this flag specifies that all Neptune ML S3 artifacts should be deleted when the job is stopped. The default is <code>FALSE</code>.</p>
    pub fn clean(&self) -> ::std::option::Option<bool> {
        self.clean
    }
}
impl CancelMlDataProcessingJobInput {
    /// Creates a new builder-style object to manufacture [`CancelMlDataProcessingJobInput`](crate::operation::cancel_ml_data_processing_job::CancelMlDataProcessingJobInput).
    pub fn builder() -> crate::operation::cancel_ml_data_processing_job::builders::CancelMlDataProcessingJobInputBuilder {
        crate::operation::cancel_ml_data_processing_job::builders::CancelMlDataProcessingJobInputBuilder::default()
    }
}

/// A builder for [`CancelMlDataProcessingJobInput`](crate::operation::cancel_ml_data_processing_job::CancelMlDataProcessingJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelMlDataProcessingJobInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) neptune_iam_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) clean: ::std::option::Option<bool>,
}
impl CancelMlDataProcessingJobInputBuilder {
    /// <p>The unique identifier of the data-processing job.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the data-processing job.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the data-processing job.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The ARN of an IAM role that provides Neptune access to SageMaker and Amazon S3 resources. This must be listed in your DB cluster parameter group or an error will occur.</p>
    pub fn neptune_iam_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.neptune_iam_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of an IAM role that provides Neptune access to SageMaker and Amazon S3 resources. This must be listed in your DB cluster parameter group or an error will occur.</p>
    pub fn set_neptune_iam_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.neptune_iam_role_arn = input;
        self
    }
    /// <p>The ARN of an IAM role that provides Neptune access to SageMaker and Amazon S3 resources. This must be listed in your DB cluster parameter group or an error will occur.</p>
    pub fn get_neptune_iam_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.neptune_iam_role_arn
    }
    /// <p>If set to <code>TRUE</code>, this flag specifies that all Neptune ML S3 artifacts should be deleted when the job is stopped. The default is <code>FALSE</code>.</p>
    pub fn clean(mut self, input: bool) -> Self {
        self.clean = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to <code>TRUE</code>, this flag specifies that all Neptune ML S3 artifacts should be deleted when the job is stopped. The default is <code>FALSE</code>.</p>
    pub fn set_clean(mut self, input: ::std::option::Option<bool>) -> Self {
        self.clean = input;
        self
    }
    /// <p>If set to <code>TRUE</code>, this flag specifies that all Neptune ML S3 artifacts should be deleted when the job is stopped. The default is <code>FALSE</code>.</p>
    pub fn get_clean(&self) -> &::std::option::Option<bool> {
        &self.clean
    }
    /// Consumes the builder and constructs a [`CancelMlDataProcessingJobInput`](crate::operation::cancel_ml_data_processing_job::CancelMlDataProcessingJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::cancel_ml_data_processing_job::CancelMlDataProcessingJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::cancel_ml_data_processing_job::CancelMlDataProcessingJobInput {
            id: self.id,
            neptune_iam_role_arn: self.neptune_iam_role_arn,
            clean: self.clean,
        })
    }
}
