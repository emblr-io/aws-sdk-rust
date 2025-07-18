// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the parameters for GetPipelineDefinition.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPipelineDefinitionInput {
    /// <p>The ID of the pipeline.</p>
    pub pipeline_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the pipeline definition to retrieve. Set this parameter to <code>latest</code> (default) to use the last definition saved to the pipeline or <code>active</code> to use the last definition that was activated.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl GetPipelineDefinitionInput {
    /// <p>The ID of the pipeline.</p>
    pub fn pipeline_id(&self) -> ::std::option::Option<&str> {
        self.pipeline_id.as_deref()
    }
    /// <p>The version of the pipeline definition to retrieve. Set this parameter to <code>latest</code> (default) to use the last definition saved to the pipeline or <code>active</code> to use the last definition that was activated.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl GetPipelineDefinitionInput {
    /// Creates a new builder-style object to manufacture [`GetPipelineDefinitionInput`](crate::operation::get_pipeline_definition::GetPipelineDefinitionInput).
    pub fn builder() -> crate::operation::get_pipeline_definition::builders::GetPipelineDefinitionInputBuilder {
        crate::operation::get_pipeline_definition::builders::GetPipelineDefinitionInputBuilder::default()
    }
}

/// A builder for [`GetPipelineDefinitionInput`](crate::operation::get_pipeline_definition::GetPipelineDefinitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPipelineDefinitionInputBuilder {
    pub(crate) pipeline_id: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl GetPipelineDefinitionInputBuilder {
    /// <p>The ID of the pipeline.</p>
    /// This field is required.
    pub fn pipeline_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the pipeline.</p>
    pub fn set_pipeline_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_id = input;
        self
    }
    /// <p>The ID of the pipeline.</p>
    pub fn get_pipeline_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_id
    }
    /// <p>The version of the pipeline definition to retrieve. Set this parameter to <code>latest</code> (default) to use the last definition saved to the pipeline or <code>active</code> to use the last definition that was activated.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the pipeline definition to retrieve. Set this parameter to <code>latest</code> (default) to use the last definition saved to the pipeline or <code>active</code> to use the last definition that was activated.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the pipeline definition to retrieve. Set this parameter to <code>latest</code> (default) to use the last definition saved to the pipeline or <code>active</code> to use the last definition that was activated.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`GetPipelineDefinitionInput`](crate::operation::get_pipeline_definition::GetPipelineDefinitionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_pipeline_definition::GetPipelineDefinitionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_pipeline_definition::GetPipelineDefinitionInput {
            pipeline_id: self.pipeline_id,
            version: self.version,
        })
    }
}
