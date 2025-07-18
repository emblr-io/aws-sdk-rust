// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of the models used in an Amazon Bedrock model evaluation job. These resources can be models in Amazon Bedrock or models outside of Amazon Bedrock that you use to generate your own inference response data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EvaluationModelConfigSummary {
    /// <p>The Amazon Resource Names (ARNs) of the models used for the evaluation job.</p>
    pub bedrock_model_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A label that identifies the models used for a model evaluation job where you provide your own inference response data.</p>
    pub precomputed_inference_source_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl EvaluationModelConfigSummary {
    /// <p>The Amazon Resource Names (ARNs) of the models used for the evaluation job.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.bedrock_model_identifiers.is_none()`.
    pub fn bedrock_model_identifiers(&self) -> &[::std::string::String] {
        self.bedrock_model_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>A label that identifies the models used for a model evaluation job where you provide your own inference response data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.precomputed_inference_source_identifiers.is_none()`.
    pub fn precomputed_inference_source_identifiers(&self) -> &[::std::string::String] {
        self.precomputed_inference_source_identifiers.as_deref().unwrap_or_default()
    }
}
impl EvaluationModelConfigSummary {
    /// Creates a new builder-style object to manufacture [`EvaluationModelConfigSummary`](crate::types::EvaluationModelConfigSummary).
    pub fn builder() -> crate::types::builders::EvaluationModelConfigSummaryBuilder {
        crate::types::builders::EvaluationModelConfigSummaryBuilder::default()
    }
}

/// A builder for [`EvaluationModelConfigSummary`](crate::types::EvaluationModelConfigSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EvaluationModelConfigSummaryBuilder {
    pub(crate) bedrock_model_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) precomputed_inference_source_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl EvaluationModelConfigSummaryBuilder {
    /// Appends an item to `bedrock_model_identifiers`.
    ///
    /// To override the contents of this collection use [`set_bedrock_model_identifiers`](Self::set_bedrock_model_identifiers).
    ///
    /// <p>The Amazon Resource Names (ARNs) of the models used for the evaluation job.</p>
    pub fn bedrock_model_identifiers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.bedrock_model_identifiers.unwrap_or_default();
        v.push(input.into());
        self.bedrock_model_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Names (ARNs) of the models used for the evaluation job.</p>
    pub fn set_bedrock_model_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.bedrock_model_identifiers = input;
        self
    }
    /// <p>The Amazon Resource Names (ARNs) of the models used for the evaluation job.</p>
    pub fn get_bedrock_model_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.bedrock_model_identifiers
    }
    /// Appends an item to `precomputed_inference_source_identifiers`.
    ///
    /// To override the contents of this collection use [`set_precomputed_inference_source_identifiers`](Self::set_precomputed_inference_source_identifiers).
    ///
    /// <p>A label that identifies the models used for a model evaluation job where you provide your own inference response data.</p>
    pub fn precomputed_inference_source_identifiers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.precomputed_inference_source_identifiers.unwrap_or_default();
        v.push(input.into());
        self.precomputed_inference_source_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>A label that identifies the models used for a model evaluation job where you provide your own inference response data.</p>
    pub fn set_precomputed_inference_source_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.precomputed_inference_source_identifiers = input;
        self
    }
    /// <p>A label that identifies the models used for a model evaluation job where you provide your own inference response data.</p>
    pub fn get_precomputed_inference_source_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.precomputed_inference_source_identifiers
    }
    /// Consumes the builder and constructs a [`EvaluationModelConfigSummary`](crate::types::EvaluationModelConfigSummary).
    pub fn build(self) -> crate::types::EvaluationModelConfigSummary {
        crate::types::EvaluationModelConfigSummary {
            bedrock_model_identifiers: self.bedrock_model_identifiers,
            precomputed_inference_source_identifiers: self.precomputed_inference_source_identifiers,
        }
    }
}
