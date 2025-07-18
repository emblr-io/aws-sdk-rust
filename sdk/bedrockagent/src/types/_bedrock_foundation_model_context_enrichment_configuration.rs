// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Context enrichment configuration is used to provide additional context to the RAG application using Amazon Bedrock foundation models.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BedrockFoundationModelContextEnrichmentConfiguration {
    /// <p>The enrichment stategy used to provide additional context. For example, Neptune GraphRAG uses Amazon Bedrock foundation models to perform chunk entity extraction.</p>
    pub enrichment_strategy_configuration: ::std::option::Option<crate::types::EnrichmentStrategyConfiguration>,
    /// <p>The Amazon Resource Name (ARN) of the model used to create vector embeddings for the knowledge base.</p>
    pub model_arn: ::std::string::String,
}
impl BedrockFoundationModelContextEnrichmentConfiguration {
    /// <p>The enrichment stategy used to provide additional context. For example, Neptune GraphRAG uses Amazon Bedrock foundation models to perform chunk entity extraction.</p>
    pub fn enrichment_strategy_configuration(&self) -> ::std::option::Option<&crate::types::EnrichmentStrategyConfiguration> {
        self.enrichment_strategy_configuration.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the model used to create vector embeddings for the knowledge base.</p>
    pub fn model_arn(&self) -> &str {
        use std::ops::Deref;
        self.model_arn.deref()
    }
}
impl BedrockFoundationModelContextEnrichmentConfiguration {
    /// Creates a new builder-style object to manufacture [`BedrockFoundationModelContextEnrichmentConfiguration`](crate::types::BedrockFoundationModelContextEnrichmentConfiguration).
    pub fn builder() -> crate::types::builders::BedrockFoundationModelContextEnrichmentConfigurationBuilder {
        crate::types::builders::BedrockFoundationModelContextEnrichmentConfigurationBuilder::default()
    }
}

/// A builder for [`BedrockFoundationModelContextEnrichmentConfiguration`](crate::types::BedrockFoundationModelContextEnrichmentConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BedrockFoundationModelContextEnrichmentConfigurationBuilder {
    pub(crate) enrichment_strategy_configuration: ::std::option::Option<crate::types::EnrichmentStrategyConfiguration>,
    pub(crate) model_arn: ::std::option::Option<::std::string::String>,
}
impl BedrockFoundationModelContextEnrichmentConfigurationBuilder {
    /// <p>The enrichment stategy used to provide additional context. For example, Neptune GraphRAG uses Amazon Bedrock foundation models to perform chunk entity extraction.</p>
    /// This field is required.
    pub fn enrichment_strategy_configuration(mut self, input: crate::types::EnrichmentStrategyConfiguration) -> Self {
        self.enrichment_strategy_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The enrichment stategy used to provide additional context. For example, Neptune GraphRAG uses Amazon Bedrock foundation models to perform chunk entity extraction.</p>
    pub fn set_enrichment_strategy_configuration(mut self, input: ::std::option::Option<crate::types::EnrichmentStrategyConfiguration>) -> Self {
        self.enrichment_strategy_configuration = input;
        self
    }
    /// <p>The enrichment stategy used to provide additional context. For example, Neptune GraphRAG uses Amazon Bedrock foundation models to perform chunk entity extraction.</p>
    pub fn get_enrichment_strategy_configuration(&self) -> &::std::option::Option<crate::types::EnrichmentStrategyConfiguration> {
        &self.enrichment_strategy_configuration
    }
    /// <p>The Amazon Resource Name (ARN) of the model used to create vector embeddings for the knowledge base.</p>
    /// This field is required.
    pub fn model_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the model used to create vector embeddings for the knowledge base.</p>
    pub fn set_model_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the model used to create vector embeddings for the knowledge base.</p>
    pub fn get_model_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_arn
    }
    /// Consumes the builder and constructs a [`BedrockFoundationModelContextEnrichmentConfiguration`](crate::types::BedrockFoundationModelContextEnrichmentConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`model_arn`](crate::types::builders::BedrockFoundationModelContextEnrichmentConfigurationBuilder::model_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::BedrockFoundationModelContextEnrichmentConfiguration, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::types::BedrockFoundationModelContextEnrichmentConfiguration {
            enrichment_strategy_configuration: self.enrichment_strategy_configuration,
            model_arn: self.model_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "model_arn",
                    "model_arn was not specified but it is required when building BedrockFoundationModelContextEnrichmentConfiguration",
                )
            })?,
        })
    }
}
