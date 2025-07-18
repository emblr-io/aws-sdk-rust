// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMlDataProcessingJobInput {
    /// <p>The unique identifier of the data-processing job to be retrieved.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of an IAM role that provides Neptune access to SageMaker and Amazon S3 resources. This must be listed in your DB cluster parameter group or an error will occur.</p>
    pub neptune_iam_role_arn: ::std::option::Option<::std::string::String>,
}
impl GetMlDataProcessingJobInput {
    /// <p>The unique identifier of the data-processing job to be retrieved.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The ARN of an IAM role that provides Neptune access to SageMaker and Amazon S3 resources. This must be listed in your DB cluster parameter group or an error will occur.</p>
    pub fn neptune_iam_role_arn(&self) -> ::std::option::Option<&str> {
        self.neptune_iam_role_arn.as_deref()
    }
}
impl GetMlDataProcessingJobInput {
    /// Creates a new builder-style object to manufacture [`GetMlDataProcessingJobInput`](crate::operation::get_ml_data_processing_job::GetMlDataProcessingJobInput).
    pub fn builder() -> crate::operation::get_ml_data_processing_job::builders::GetMlDataProcessingJobInputBuilder {
        crate::operation::get_ml_data_processing_job::builders::GetMlDataProcessingJobInputBuilder::default()
    }
}

/// A builder for [`GetMlDataProcessingJobInput`](crate::operation::get_ml_data_processing_job::GetMlDataProcessingJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMlDataProcessingJobInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) neptune_iam_role_arn: ::std::option::Option<::std::string::String>,
}
impl GetMlDataProcessingJobInputBuilder {
    /// <p>The unique identifier of the data-processing job to be retrieved.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the data-processing job to be retrieved.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the data-processing job to be retrieved.</p>
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
    /// Consumes the builder and constructs a [`GetMlDataProcessingJobInput`](crate::operation::get_ml_data_processing_job::GetMlDataProcessingJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_ml_data_processing_job::GetMlDataProcessingJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_ml_data_processing_job::GetMlDataProcessingJobInput {
            id: self.id,
            neptune_iam_role_arn: self.neptune_iam_role_arn,
        })
    }
}
