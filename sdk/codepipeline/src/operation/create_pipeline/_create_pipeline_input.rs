// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>CreatePipeline</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePipelineInput {
    /// <p>Represents the structure of actions and stages to be performed in the pipeline.</p>
    pub pipeline: ::std::option::Option<crate::types::PipelineDeclaration>,
    /// <p>The tags for the pipeline.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreatePipelineInput {
    /// <p>Represents the structure of actions and stages to be performed in the pipeline.</p>
    pub fn pipeline(&self) -> ::std::option::Option<&crate::types::PipelineDeclaration> {
        self.pipeline.as_ref()
    }
    /// <p>The tags for the pipeline.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreatePipelineInput {
    /// Creates a new builder-style object to manufacture [`CreatePipelineInput`](crate::operation::create_pipeline::CreatePipelineInput).
    pub fn builder() -> crate::operation::create_pipeline::builders::CreatePipelineInputBuilder {
        crate::operation::create_pipeline::builders::CreatePipelineInputBuilder::default()
    }
}

/// A builder for [`CreatePipelineInput`](crate::operation::create_pipeline::CreatePipelineInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePipelineInputBuilder {
    pub(crate) pipeline: ::std::option::Option<crate::types::PipelineDeclaration>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreatePipelineInputBuilder {
    /// <p>Represents the structure of actions and stages to be performed in the pipeline.</p>
    /// This field is required.
    pub fn pipeline(mut self, input: crate::types::PipelineDeclaration) -> Self {
        self.pipeline = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents the structure of actions and stages to be performed in the pipeline.</p>
    pub fn set_pipeline(mut self, input: ::std::option::Option<crate::types::PipelineDeclaration>) -> Self {
        self.pipeline = input;
        self
    }
    /// <p>Represents the structure of actions and stages to be performed in the pipeline.</p>
    pub fn get_pipeline(&self) -> &::std::option::Option<crate::types::PipelineDeclaration> {
        &self.pipeline
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags for the pipeline.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags for the pipeline.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags for the pipeline.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreatePipelineInput`](crate::operation::create_pipeline::CreatePipelineInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_pipeline::CreatePipelineInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_pipeline::CreatePipelineInput {
            pipeline: self.pipeline,
            tags: self.tags,
        })
    }
}
