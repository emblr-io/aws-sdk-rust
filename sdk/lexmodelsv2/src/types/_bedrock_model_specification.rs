// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the Amazon Bedrock model used to interpret the prompt used in descriptive bot building.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BedrockModelSpecification {
    /// <p>The ARN of the foundation model used in descriptive bot building.</p>
    pub model_arn: ::std::string::String,
    /// <p>The guardrail configuration in the Bedrock model specification details.</p>
    pub guardrail: ::std::option::Option<crate::types::BedrockGuardrailConfiguration>,
    /// <p>The Bedrock trace status in the Bedrock model specification details.</p>
    pub trace_status: ::std::option::Option<crate::types::BedrockTraceStatus>,
    /// <p>The custom prompt used in the Bedrock model specification details.</p>
    pub custom_prompt: ::std::option::Option<::std::string::String>,
}
impl BedrockModelSpecification {
    /// <p>The ARN of the foundation model used in descriptive bot building.</p>
    pub fn model_arn(&self) -> &str {
        use std::ops::Deref;
        self.model_arn.deref()
    }
    /// <p>The guardrail configuration in the Bedrock model specification details.</p>
    pub fn guardrail(&self) -> ::std::option::Option<&crate::types::BedrockGuardrailConfiguration> {
        self.guardrail.as_ref()
    }
    /// <p>The Bedrock trace status in the Bedrock model specification details.</p>
    pub fn trace_status(&self) -> ::std::option::Option<&crate::types::BedrockTraceStatus> {
        self.trace_status.as_ref()
    }
    /// <p>The custom prompt used in the Bedrock model specification details.</p>
    pub fn custom_prompt(&self) -> ::std::option::Option<&str> {
        self.custom_prompt.as_deref()
    }
}
impl BedrockModelSpecification {
    /// Creates a new builder-style object to manufacture [`BedrockModelSpecification`](crate::types::BedrockModelSpecification).
    pub fn builder() -> crate::types::builders::BedrockModelSpecificationBuilder {
        crate::types::builders::BedrockModelSpecificationBuilder::default()
    }
}

/// A builder for [`BedrockModelSpecification`](crate::types::BedrockModelSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BedrockModelSpecificationBuilder {
    pub(crate) model_arn: ::std::option::Option<::std::string::String>,
    pub(crate) guardrail: ::std::option::Option<crate::types::BedrockGuardrailConfiguration>,
    pub(crate) trace_status: ::std::option::Option<crate::types::BedrockTraceStatus>,
    pub(crate) custom_prompt: ::std::option::Option<::std::string::String>,
}
impl BedrockModelSpecificationBuilder {
    /// <p>The ARN of the foundation model used in descriptive bot building.</p>
    /// This field is required.
    pub fn model_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the foundation model used in descriptive bot building.</p>
    pub fn set_model_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_arn = input;
        self
    }
    /// <p>The ARN of the foundation model used in descriptive bot building.</p>
    pub fn get_model_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_arn
    }
    /// <p>The guardrail configuration in the Bedrock model specification details.</p>
    pub fn guardrail(mut self, input: crate::types::BedrockGuardrailConfiguration) -> Self {
        self.guardrail = ::std::option::Option::Some(input);
        self
    }
    /// <p>The guardrail configuration in the Bedrock model specification details.</p>
    pub fn set_guardrail(mut self, input: ::std::option::Option<crate::types::BedrockGuardrailConfiguration>) -> Self {
        self.guardrail = input;
        self
    }
    /// <p>The guardrail configuration in the Bedrock model specification details.</p>
    pub fn get_guardrail(&self) -> &::std::option::Option<crate::types::BedrockGuardrailConfiguration> {
        &self.guardrail
    }
    /// <p>The Bedrock trace status in the Bedrock model specification details.</p>
    pub fn trace_status(mut self, input: crate::types::BedrockTraceStatus) -> Self {
        self.trace_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Bedrock trace status in the Bedrock model specification details.</p>
    pub fn set_trace_status(mut self, input: ::std::option::Option<crate::types::BedrockTraceStatus>) -> Self {
        self.trace_status = input;
        self
    }
    /// <p>The Bedrock trace status in the Bedrock model specification details.</p>
    pub fn get_trace_status(&self) -> &::std::option::Option<crate::types::BedrockTraceStatus> {
        &self.trace_status
    }
    /// <p>The custom prompt used in the Bedrock model specification details.</p>
    pub fn custom_prompt(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_prompt = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom prompt used in the Bedrock model specification details.</p>
    pub fn set_custom_prompt(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_prompt = input;
        self
    }
    /// <p>The custom prompt used in the Bedrock model specification details.</p>
    pub fn get_custom_prompt(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_prompt
    }
    /// Consumes the builder and constructs a [`BedrockModelSpecification`](crate::types::BedrockModelSpecification).
    /// This method will fail if any of the following fields are not set:
    /// - [`model_arn`](crate::types::builders::BedrockModelSpecificationBuilder::model_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::BedrockModelSpecification, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BedrockModelSpecification {
            model_arn: self.model_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "model_arn",
                    "model_arn was not specified but it is required when building BedrockModelSpecification",
                )
            })?,
            guardrail: self.guardrail,
            trace_status: self.trace_status,
            custom_prompt: self.custom_prompt,
        })
    }
}
