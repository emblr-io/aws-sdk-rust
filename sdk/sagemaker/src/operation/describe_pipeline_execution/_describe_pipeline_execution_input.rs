// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribePipelineExecutionInput {
    /// <p>The Amazon Resource Name (ARN) of the pipeline execution.</p>
    pub pipeline_execution_arn: ::std::option::Option<::std::string::String>,
}
impl DescribePipelineExecutionInput {
    /// <p>The Amazon Resource Name (ARN) of the pipeline execution.</p>
    pub fn pipeline_execution_arn(&self) -> ::std::option::Option<&str> {
        self.pipeline_execution_arn.as_deref()
    }
}
impl DescribePipelineExecutionInput {
    /// Creates a new builder-style object to manufacture [`DescribePipelineExecutionInput`](crate::operation::describe_pipeline_execution::DescribePipelineExecutionInput).
    pub fn builder() -> crate::operation::describe_pipeline_execution::builders::DescribePipelineExecutionInputBuilder {
        crate::operation::describe_pipeline_execution::builders::DescribePipelineExecutionInputBuilder::default()
    }
}

/// A builder for [`DescribePipelineExecutionInput`](crate::operation::describe_pipeline_execution::DescribePipelineExecutionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribePipelineExecutionInputBuilder {
    pub(crate) pipeline_execution_arn: ::std::option::Option<::std::string::String>,
}
impl DescribePipelineExecutionInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the pipeline execution.</p>
    /// This field is required.
    pub fn pipeline_execution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_execution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline execution.</p>
    pub fn set_pipeline_execution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_execution_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline execution.</p>
    pub fn get_pipeline_execution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_execution_arn
    }
    /// Consumes the builder and constructs a [`DescribePipelineExecutionInput`](crate::operation::describe_pipeline_execution::DescribePipelineExecutionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_pipeline_execution::DescribePipelineExecutionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_pipeline_execution::DescribePipelineExecutionInput {
            pipeline_execution_arn: self.pipeline_execution_arn,
        })
    }
}
