// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents information about a pipeline to a job worker.</p><note>
/// <p>PipelineContext contains <code>pipelineArn</code> and <code>pipelineExecutionId</code> for custom action jobs. The <code>pipelineArn</code> and <code>pipelineExecutionId</code> fields are not populated for ThirdParty action jobs.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PipelineContext {
    /// <p>The name of the pipeline. This is a user-specified value. Pipeline names must be unique across all pipeline names under an Amazon Web Services account.</p>
    pub pipeline_name: ::std::option::Option<::std::string::String>,
    /// <p>The stage of the pipeline.</p>
    pub stage: ::std::option::Option<crate::types::StageContext>,
    /// <p>The context of an action to a job worker in the stage of a pipeline.</p>
    pub action: ::std::option::Option<crate::types::ActionContext>,
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub pipeline_arn: ::std::option::Option<::std::string::String>,
    /// <p>The execution ID of the pipeline.</p>
    pub pipeline_execution_id: ::std::option::Option<::std::string::String>,
}
impl PipelineContext {
    /// <p>The name of the pipeline. This is a user-specified value. Pipeline names must be unique across all pipeline names under an Amazon Web Services account.</p>
    pub fn pipeline_name(&self) -> ::std::option::Option<&str> {
        self.pipeline_name.as_deref()
    }
    /// <p>The stage of the pipeline.</p>
    pub fn stage(&self) -> ::std::option::Option<&crate::types::StageContext> {
        self.stage.as_ref()
    }
    /// <p>The context of an action to a job worker in the stage of a pipeline.</p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::ActionContext> {
        self.action.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub fn pipeline_arn(&self) -> ::std::option::Option<&str> {
        self.pipeline_arn.as_deref()
    }
    /// <p>The execution ID of the pipeline.</p>
    pub fn pipeline_execution_id(&self) -> ::std::option::Option<&str> {
        self.pipeline_execution_id.as_deref()
    }
}
impl PipelineContext {
    /// Creates a new builder-style object to manufacture [`PipelineContext`](crate::types::PipelineContext).
    pub fn builder() -> crate::types::builders::PipelineContextBuilder {
        crate::types::builders::PipelineContextBuilder::default()
    }
}

/// A builder for [`PipelineContext`](crate::types::PipelineContext).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PipelineContextBuilder {
    pub(crate) pipeline_name: ::std::option::Option<::std::string::String>,
    pub(crate) stage: ::std::option::Option<crate::types::StageContext>,
    pub(crate) action: ::std::option::Option<crate::types::ActionContext>,
    pub(crate) pipeline_arn: ::std::option::Option<::std::string::String>,
    pub(crate) pipeline_execution_id: ::std::option::Option<::std::string::String>,
}
impl PipelineContextBuilder {
    /// <p>The name of the pipeline. This is a user-specified value. Pipeline names must be unique across all pipeline names under an Amazon Web Services account.</p>
    pub fn pipeline_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the pipeline. This is a user-specified value. Pipeline names must be unique across all pipeline names under an Amazon Web Services account.</p>
    pub fn set_pipeline_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_name = input;
        self
    }
    /// <p>The name of the pipeline. This is a user-specified value. Pipeline names must be unique across all pipeline names under an Amazon Web Services account.</p>
    pub fn get_pipeline_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_name
    }
    /// <p>The stage of the pipeline.</p>
    pub fn stage(mut self, input: crate::types::StageContext) -> Self {
        self.stage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The stage of the pipeline.</p>
    pub fn set_stage(mut self, input: ::std::option::Option<crate::types::StageContext>) -> Self {
        self.stage = input;
        self
    }
    /// <p>The stage of the pipeline.</p>
    pub fn get_stage(&self) -> &::std::option::Option<crate::types::StageContext> {
        &self.stage
    }
    /// <p>The context of an action to a job worker in the stage of a pipeline.</p>
    pub fn action(mut self, input: crate::types::ActionContext) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The context of an action to a job worker in the stage of a pipeline.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::ActionContext>) -> Self {
        self.action = input;
        self
    }
    /// <p>The context of an action to a job worker in the stage of a pipeline.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::ActionContext> {
        &self.action
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub fn pipeline_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub fn set_pipeline_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub fn get_pipeline_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_arn
    }
    /// <p>The execution ID of the pipeline.</p>
    pub fn pipeline_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The execution ID of the pipeline.</p>
    pub fn set_pipeline_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_execution_id = input;
        self
    }
    /// <p>The execution ID of the pipeline.</p>
    pub fn get_pipeline_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_execution_id
    }
    /// Consumes the builder and constructs a [`PipelineContext`](crate::types::PipelineContext).
    pub fn build(self) -> crate::types::PipelineContext {
        crate::types::PipelineContext {
            pipeline_name: self.pipeline_name,
            stage: self.stage,
            action: self.action,
            pipeline_arn: self.pipeline_arn,
            pipeline_execution_id: self.pipeline_execution_id,
        }
    }
}
