// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Metadata about a callback step.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CallbackStepMetadata {
    /// <p>The pipeline generated token from the Amazon SQS queue.</p>
    pub callback_token: ::std::option::Option<::std::string::String>,
    /// <p>The URL of the Amazon Simple Queue Service (Amazon SQS) queue used by the callback step.</p>
    pub sqs_queue_url: ::std::option::Option<::std::string::String>,
    /// <p>A list of the output parameters of the callback step.</p>
    pub output_parameters: ::std::option::Option<::std::vec::Vec<crate::types::OutputParameter>>,
}
impl CallbackStepMetadata {
    /// <p>The pipeline generated token from the Amazon SQS queue.</p>
    pub fn callback_token(&self) -> ::std::option::Option<&str> {
        self.callback_token.as_deref()
    }
    /// <p>The URL of the Amazon Simple Queue Service (Amazon SQS) queue used by the callback step.</p>
    pub fn sqs_queue_url(&self) -> ::std::option::Option<&str> {
        self.sqs_queue_url.as_deref()
    }
    /// <p>A list of the output parameters of the callback step.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.output_parameters.is_none()`.
    pub fn output_parameters(&self) -> &[crate::types::OutputParameter] {
        self.output_parameters.as_deref().unwrap_or_default()
    }
}
impl CallbackStepMetadata {
    /// Creates a new builder-style object to manufacture [`CallbackStepMetadata`](crate::types::CallbackStepMetadata).
    pub fn builder() -> crate::types::builders::CallbackStepMetadataBuilder {
        crate::types::builders::CallbackStepMetadataBuilder::default()
    }
}

/// A builder for [`CallbackStepMetadata`](crate::types::CallbackStepMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CallbackStepMetadataBuilder {
    pub(crate) callback_token: ::std::option::Option<::std::string::String>,
    pub(crate) sqs_queue_url: ::std::option::Option<::std::string::String>,
    pub(crate) output_parameters: ::std::option::Option<::std::vec::Vec<crate::types::OutputParameter>>,
}
impl CallbackStepMetadataBuilder {
    /// <p>The pipeline generated token from the Amazon SQS queue.</p>
    pub fn callback_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.callback_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pipeline generated token from the Amazon SQS queue.</p>
    pub fn set_callback_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.callback_token = input;
        self
    }
    /// <p>The pipeline generated token from the Amazon SQS queue.</p>
    pub fn get_callback_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.callback_token
    }
    /// <p>The URL of the Amazon Simple Queue Service (Amazon SQS) queue used by the callback step.</p>
    pub fn sqs_queue_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sqs_queue_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the Amazon Simple Queue Service (Amazon SQS) queue used by the callback step.</p>
    pub fn set_sqs_queue_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sqs_queue_url = input;
        self
    }
    /// <p>The URL of the Amazon Simple Queue Service (Amazon SQS) queue used by the callback step.</p>
    pub fn get_sqs_queue_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.sqs_queue_url
    }
    /// Appends an item to `output_parameters`.
    ///
    /// To override the contents of this collection use [`set_output_parameters`](Self::set_output_parameters).
    ///
    /// <p>A list of the output parameters of the callback step.</p>
    pub fn output_parameters(mut self, input: crate::types::OutputParameter) -> Self {
        let mut v = self.output_parameters.unwrap_or_default();
        v.push(input);
        self.output_parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the output parameters of the callback step.</p>
    pub fn set_output_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OutputParameter>>) -> Self {
        self.output_parameters = input;
        self
    }
    /// <p>A list of the output parameters of the callback step.</p>
    pub fn get_output_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OutputParameter>> {
        &self.output_parameters
    }
    /// Consumes the builder and constructs a [`CallbackStepMetadata`](crate::types::CallbackStepMetadata).
    pub fn build(self) -> crate::types::CallbackStepMetadata {
        crate::types::CallbackStepMetadata {
            callback_token: self.callback_token,
            sqs_queue_url: self.sqs_queue_url,
            output_parameters: self.output_parameters,
        }
    }
}
