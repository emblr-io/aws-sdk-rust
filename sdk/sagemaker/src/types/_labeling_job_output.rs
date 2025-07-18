// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the location of the output produced by the labeling job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LabelingJobOutput {
    /// <p>The Amazon S3 bucket location of the manifest file for labeled data.</p>
    pub output_dataset_s3_uri: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for the most recent SageMaker model trained as part of automated data labeling.</p>
    pub final_active_learning_model_arn: ::std::option::Option<::std::string::String>,
}
impl LabelingJobOutput {
    /// <p>The Amazon S3 bucket location of the manifest file for labeled data.</p>
    pub fn output_dataset_s3_uri(&self) -> ::std::option::Option<&str> {
        self.output_dataset_s3_uri.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for the most recent SageMaker model trained as part of automated data labeling.</p>
    pub fn final_active_learning_model_arn(&self) -> ::std::option::Option<&str> {
        self.final_active_learning_model_arn.as_deref()
    }
}
impl LabelingJobOutput {
    /// Creates a new builder-style object to manufacture [`LabelingJobOutput`](crate::types::LabelingJobOutput).
    pub fn builder() -> crate::types::builders::LabelingJobOutputBuilder {
        crate::types::builders::LabelingJobOutputBuilder::default()
    }
}

/// A builder for [`LabelingJobOutput`](crate::types::LabelingJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LabelingJobOutputBuilder {
    pub(crate) output_dataset_s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) final_active_learning_model_arn: ::std::option::Option<::std::string::String>,
}
impl LabelingJobOutputBuilder {
    /// <p>The Amazon S3 bucket location of the manifest file for labeled data.</p>
    /// This field is required.
    pub fn output_dataset_s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.output_dataset_s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 bucket location of the manifest file for labeled data.</p>
    pub fn set_output_dataset_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.output_dataset_s3_uri = input;
        self
    }
    /// <p>The Amazon S3 bucket location of the manifest file for labeled data.</p>
    pub fn get_output_dataset_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.output_dataset_s3_uri
    }
    /// <p>The Amazon Resource Name (ARN) for the most recent SageMaker model trained as part of automated data labeling.</p>
    pub fn final_active_learning_model_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.final_active_learning_model_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the most recent SageMaker model trained as part of automated data labeling.</p>
    pub fn set_final_active_learning_model_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.final_active_learning_model_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the most recent SageMaker model trained as part of automated data labeling.</p>
    pub fn get_final_active_learning_model_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.final_active_learning_model_arn
    }
    /// Consumes the builder and constructs a [`LabelingJobOutput`](crate::types::LabelingJobOutput).
    pub fn build(self) -> crate::types::LabelingJobOutput {
        crate::types::LabelingJobOutput {
            output_dataset_s3_uri: self.output_dataset_s3_uri,
            final_active_learning_model_arn: self.final_active_learning_model_arn,
        }
    }
}
