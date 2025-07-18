// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of an <code>UpdatePipeline</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdatePipelineInput {
    /// <p>The name of the pipeline to be updated.</p>
    pub pipeline: ::std::option::Option<crate::types::PipelineDeclaration>,
}
impl UpdatePipelineInput {
    /// <p>The name of the pipeline to be updated.</p>
    pub fn pipeline(&self) -> ::std::option::Option<&crate::types::PipelineDeclaration> {
        self.pipeline.as_ref()
    }
}
impl UpdatePipelineInput {
    /// Creates a new builder-style object to manufacture [`UpdatePipelineInput`](crate::operation::update_pipeline::UpdatePipelineInput).
    pub fn builder() -> crate::operation::update_pipeline::builders::UpdatePipelineInputBuilder {
        crate::operation::update_pipeline::builders::UpdatePipelineInputBuilder::default()
    }
}

/// A builder for [`UpdatePipelineInput`](crate::operation::update_pipeline::UpdatePipelineInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdatePipelineInputBuilder {
    pub(crate) pipeline: ::std::option::Option<crate::types::PipelineDeclaration>,
}
impl UpdatePipelineInputBuilder {
    /// <p>The name of the pipeline to be updated.</p>
    /// This field is required.
    pub fn pipeline(mut self, input: crate::types::PipelineDeclaration) -> Self {
        self.pipeline = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the pipeline to be updated.</p>
    pub fn set_pipeline(mut self, input: ::std::option::Option<crate::types::PipelineDeclaration>) -> Self {
        self.pipeline = input;
        self
    }
    /// <p>The name of the pipeline to be updated.</p>
    pub fn get_pipeline(&self) -> &::std::option::Option<crate::types::PipelineDeclaration> {
        &self.pipeline
    }
    /// Consumes the builder and constructs a [`UpdatePipelineInput`](crate::operation::update_pipeline::UpdatePipelineInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_pipeline::UpdatePipelineInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_pipeline::UpdatePipelineInput { pipeline: self.pipeline })
    }
}
