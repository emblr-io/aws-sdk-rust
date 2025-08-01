// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The response generation configuration of the external source wrapper object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExternalSourcesGenerationConfiguration {
    /// <p>Contains the template for the prompt for the external source wrapper object.</p>
    pub prompt_template: ::std::option::Option<crate::types::PromptTemplate>,
    /// <p>Configuration details for the guardrail.</p>
    pub guardrail_configuration: ::std::option::Option<crate::types::GuardrailConfiguration>,
    /// <p>Configuration details for inference when using <code>RetrieveAndGenerate</code> to generate responses while using an external source.</p>
    pub kb_inference_config: ::std::option::Option<crate::types::KbInferenceConfig>,
    /// <p>Additional model parameters and their corresponding values not included in the text inference configuration for an external source. Takes in custom model parameters specific to the language model being used.</p>
    pub additional_model_request_fields: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::aws_smithy_types::Document>>,
}
impl ExternalSourcesGenerationConfiguration {
    /// <p>Contains the template for the prompt for the external source wrapper object.</p>
    pub fn prompt_template(&self) -> ::std::option::Option<&crate::types::PromptTemplate> {
        self.prompt_template.as_ref()
    }
    /// <p>Configuration details for the guardrail.</p>
    pub fn guardrail_configuration(&self) -> ::std::option::Option<&crate::types::GuardrailConfiguration> {
        self.guardrail_configuration.as_ref()
    }
    /// <p>Configuration details for inference when using <code>RetrieveAndGenerate</code> to generate responses while using an external source.</p>
    pub fn kb_inference_config(&self) -> ::std::option::Option<&crate::types::KbInferenceConfig> {
        self.kb_inference_config.as_ref()
    }
    /// <p>Additional model parameters and their corresponding values not included in the text inference configuration for an external source. Takes in custom model parameters specific to the language model being used.</p>
    pub fn additional_model_request_fields(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::aws_smithy_types::Document>> {
        self.additional_model_request_fields.as_ref()
    }
}
impl ExternalSourcesGenerationConfiguration {
    /// Creates a new builder-style object to manufacture [`ExternalSourcesGenerationConfiguration`](crate::types::ExternalSourcesGenerationConfiguration).
    pub fn builder() -> crate::types::builders::ExternalSourcesGenerationConfigurationBuilder {
        crate::types::builders::ExternalSourcesGenerationConfigurationBuilder::default()
    }
}

/// A builder for [`ExternalSourcesGenerationConfiguration`](crate::types::ExternalSourcesGenerationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExternalSourcesGenerationConfigurationBuilder {
    pub(crate) prompt_template: ::std::option::Option<crate::types::PromptTemplate>,
    pub(crate) guardrail_configuration: ::std::option::Option<crate::types::GuardrailConfiguration>,
    pub(crate) kb_inference_config: ::std::option::Option<crate::types::KbInferenceConfig>,
    pub(crate) additional_model_request_fields:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, ::aws_smithy_types::Document>>,
}
impl ExternalSourcesGenerationConfigurationBuilder {
    /// <p>Contains the template for the prompt for the external source wrapper object.</p>
    pub fn prompt_template(mut self, input: crate::types::PromptTemplate) -> Self {
        self.prompt_template = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the template for the prompt for the external source wrapper object.</p>
    pub fn set_prompt_template(mut self, input: ::std::option::Option<crate::types::PromptTemplate>) -> Self {
        self.prompt_template = input;
        self
    }
    /// <p>Contains the template for the prompt for the external source wrapper object.</p>
    pub fn get_prompt_template(&self) -> &::std::option::Option<crate::types::PromptTemplate> {
        &self.prompt_template
    }
    /// <p>Configuration details for the guardrail.</p>
    pub fn guardrail_configuration(mut self, input: crate::types::GuardrailConfiguration) -> Self {
        self.guardrail_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration details for the guardrail.</p>
    pub fn set_guardrail_configuration(mut self, input: ::std::option::Option<crate::types::GuardrailConfiguration>) -> Self {
        self.guardrail_configuration = input;
        self
    }
    /// <p>Configuration details for the guardrail.</p>
    pub fn get_guardrail_configuration(&self) -> &::std::option::Option<crate::types::GuardrailConfiguration> {
        &self.guardrail_configuration
    }
    /// <p>Configuration details for inference when using <code>RetrieveAndGenerate</code> to generate responses while using an external source.</p>
    pub fn kb_inference_config(mut self, input: crate::types::KbInferenceConfig) -> Self {
        self.kb_inference_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration details for inference when using <code>RetrieveAndGenerate</code> to generate responses while using an external source.</p>
    pub fn set_kb_inference_config(mut self, input: ::std::option::Option<crate::types::KbInferenceConfig>) -> Self {
        self.kb_inference_config = input;
        self
    }
    /// <p>Configuration details for inference when using <code>RetrieveAndGenerate</code> to generate responses while using an external source.</p>
    pub fn get_kb_inference_config(&self) -> &::std::option::Option<crate::types::KbInferenceConfig> {
        &self.kb_inference_config
    }
    /// Adds a key-value pair to `additional_model_request_fields`.
    ///
    /// To override the contents of this collection use [`set_additional_model_request_fields`](Self::set_additional_model_request_fields).
    ///
    /// <p>Additional model parameters and their corresponding values not included in the text inference configuration for an external source. Takes in custom model parameters specific to the language model being used.</p>
    pub fn additional_model_request_fields(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::aws_smithy_types::Document) -> Self {
        let mut hash_map = self.additional_model_request_fields.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.additional_model_request_fields = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Additional model parameters and their corresponding values not included in the text inference configuration for an external source. Takes in custom model parameters specific to the language model being used.</p>
    pub fn set_additional_model_request_fields(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::aws_smithy_types::Document>>,
    ) -> Self {
        self.additional_model_request_fields = input;
        self
    }
    /// <p>Additional model parameters and their corresponding values not included in the text inference configuration for an external source. Takes in custom model parameters specific to the language model being used.</p>
    pub fn get_additional_model_request_fields(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::aws_smithy_types::Document>> {
        &self.additional_model_request_fields
    }
    /// Consumes the builder and constructs a [`ExternalSourcesGenerationConfiguration`](crate::types::ExternalSourcesGenerationConfiguration).
    pub fn build(self) -> crate::types::ExternalSourcesGenerationConfiguration {
        crate::types::ExternalSourcesGenerationConfiguration {
            prompt_template: self.prompt_template,
            guardrail_configuration: self.guardrail_configuration,
            kb_inference_config: self.kb_inference_config,
            additional_model_request_fields: self.additional_model_request_fields,
        }
    }
}
