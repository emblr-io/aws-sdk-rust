// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>GetPipelineExecution</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPipelineExecutionInput {
    /// <p>The name of the pipeline about which you want to get execution details.</p>
    pub pipeline_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the pipeline execution about which you want to get execution details.</p>
    pub pipeline_execution_id: ::std::option::Option<::std::string::String>,
}
impl GetPipelineExecutionInput {
    /// <p>The name of the pipeline about which you want to get execution details.</p>
    pub fn pipeline_name(&self) -> ::std::option::Option<&str> {
        self.pipeline_name.as_deref()
    }
    /// <p>The ID of the pipeline execution about which you want to get execution details.</p>
    pub fn pipeline_execution_id(&self) -> ::std::option::Option<&str> {
        self.pipeline_execution_id.as_deref()
    }
}
impl GetPipelineExecutionInput {
    /// Creates a new builder-style object to manufacture [`GetPipelineExecutionInput`](crate::operation::get_pipeline_execution::GetPipelineExecutionInput).
    pub fn builder() -> crate::operation::get_pipeline_execution::builders::GetPipelineExecutionInputBuilder {
        crate::operation::get_pipeline_execution::builders::GetPipelineExecutionInputBuilder::default()
    }
}

/// A builder for [`GetPipelineExecutionInput`](crate::operation::get_pipeline_execution::GetPipelineExecutionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPipelineExecutionInputBuilder {
    pub(crate) pipeline_name: ::std::option::Option<::std::string::String>,
    pub(crate) pipeline_execution_id: ::std::option::Option<::std::string::String>,
}
impl GetPipelineExecutionInputBuilder {
    /// <p>The name of the pipeline about which you want to get execution details.</p>
    /// This field is required.
    pub fn pipeline_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the pipeline about which you want to get execution details.</p>
    pub fn set_pipeline_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_name = input;
        self
    }
    /// <p>The name of the pipeline about which you want to get execution details.</p>
    pub fn get_pipeline_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_name
    }
    /// <p>The ID of the pipeline execution about which you want to get execution details.</p>
    /// This field is required.
    pub fn pipeline_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the pipeline execution about which you want to get execution details.</p>
    pub fn set_pipeline_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_execution_id = input;
        self
    }
    /// <p>The ID of the pipeline execution about which you want to get execution details.</p>
    pub fn get_pipeline_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_execution_id
    }
    /// Consumes the builder and constructs a [`GetPipelineExecutionInput`](crate::operation::get_pipeline_execution::GetPipelineExecutionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_pipeline_execution::GetPipelineExecutionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_pipeline_execution::GetPipelineExecutionInput {
            pipeline_name: self.pipeline_name,
            pipeline_execution_id: self.pipeline_execution_id,
        })
    }
}
