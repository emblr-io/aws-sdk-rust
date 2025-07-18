// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents information about the run of a stage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StageExecution {
    /// <p>The ID of the pipeline execution associated with the stage.</p>
    pub pipeline_execution_id: ::std::string::String,
    /// <p>The status of the stage, or for a completed stage, the last status of the stage.</p><note>
    /// <p>A status of cancelled means that the pipeline’s definition was updated before the stage execution could be completed.</p>
    /// </note>
    pub status: crate::types::StageExecutionStatus,
    /// <p>The type of pipeline execution for the stage, such as a rollback pipeline execution.</p>
    pub r#type: ::std::option::Option<crate::types::ExecutionType>,
}
impl StageExecution {
    /// <p>The ID of the pipeline execution associated with the stage.</p>
    pub fn pipeline_execution_id(&self) -> &str {
        use std::ops::Deref;
        self.pipeline_execution_id.deref()
    }
    /// <p>The status of the stage, or for a completed stage, the last status of the stage.</p><note>
    /// <p>A status of cancelled means that the pipeline’s definition was updated before the stage execution could be completed.</p>
    /// </note>
    pub fn status(&self) -> &crate::types::StageExecutionStatus {
        &self.status
    }
    /// <p>The type of pipeline execution for the stage, such as a rollback pipeline execution.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ExecutionType> {
        self.r#type.as_ref()
    }
}
impl StageExecution {
    /// Creates a new builder-style object to manufacture [`StageExecution`](crate::types::StageExecution).
    pub fn builder() -> crate::types::builders::StageExecutionBuilder {
        crate::types::builders::StageExecutionBuilder::default()
    }
}

/// A builder for [`StageExecution`](crate::types::StageExecution).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StageExecutionBuilder {
    pub(crate) pipeline_execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::StageExecutionStatus>,
    pub(crate) r#type: ::std::option::Option<crate::types::ExecutionType>,
}
impl StageExecutionBuilder {
    /// <p>The ID of the pipeline execution associated with the stage.</p>
    /// This field is required.
    pub fn pipeline_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the pipeline execution associated with the stage.</p>
    pub fn set_pipeline_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_execution_id = input;
        self
    }
    /// <p>The ID of the pipeline execution associated with the stage.</p>
    pub fn get_pipeline_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_execution_id
    }
    /// <p>The status of the stage, or for a completed stage, the last status of the stage.</p><note>
    /// <p>A status of cancelled means that the pipeline’s definition was updated before the stage execution could be completed.</p>
    /// </note>
    /// This field is required.
    pub fn status(mut self, input: crate::types::StageExecutionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the stage, or for a completed stage, the last status of the stage.</p><note>
    /// <p>A status of cancelled means that the pipeline’s definition was updated before the stage execution could be completed.</p>
    /// </note>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::StageExecutionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the stage, or for a completed stage, the last status of the stage.</p><note>
    /// <p>A status of cancelled means that the pipeline’s definition was updated before the stage execution could be completed.</p>
    /// </note>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::StageExecutionStatus> {
        &self.status
    }
    /// <p>The type of pipeline execution for the stage, such as a rollback pipeline execution.</p>
    pub fn r#type(mut self, input: crate::types::ExecutionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of pipeline execution for the stage, such as a rollback pipeline execution.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ExecutionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of pipeline execution for the stage, such as a rollback pipeline execution.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ExecutionType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`StageExecution`](crate::types::StageExecution).
    /// This method will fail if any of the following fields are not set:
    /// - [`pipeline_execution_id`](crate::types::builders::StageExecutionBuilder::pipeline_execution_id)
    /// - [`status`](crate::types::builders::StageExecutionBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::StageExecution, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StageExecution {
            pipeline_execution_id: self.pipeline_execution_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pipeline_execution_id",
                    "pipeline_execution_id was not specified but it is required when building StageExecution",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building StageExecution",
                )
            })?,
            r#type: self.r#type,
        })
    }
}
