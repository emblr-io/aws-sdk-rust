// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLanguageModelOutput {
    /// <p>Provides information about the specified custom language model.</p>
    /// <p>This parameter also shows if the base language model you used to create your custom language model has been updated. If Amazon Transcribe has updated the base model, you can create a new custom language model using the updated base model.</p>
    /// <p>If you tried to create a new custom language model and the request wasn't successful, you can use this <code>DescribeLanguageModel</code> to help identify the reason for this failure.</p>
    pub language_model: ::std::option::Option<crate::types::LanguageModel>,
    _request_id: Option<String>,
}
impl DescribeLanguageModelOutput {
    /// <p>Provides information about the specified custom language model.</p>
    /// <p>This parameter also shows if the base language model you used to create your custom language model has been updated. If Amazon Transcribe has updated the base model, you can create a new custom language model using the updated base model.</p>
    /// <p>If you tried to create a new custom language model and the request wasn't successful, you can use this <code>DescribeLanguageModel</code> to help identify the reason for this failure.</p>
    pub fn language_model(&self) -> ::std::option::Option<&crate::types::LanguageModel> {
        self.language_model.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeLanguageModelOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeLanguageModelOutput {
    /// Creates a new builder-style object to manufacture [`DescribeLanguageModelOutput`](crate::operation::describe_language_model::DescribeLanguageModelOutput).
    pub fn builder() -> crate::operation::describe_language_model::builders::DescribeLanguageModelOutputBuilder {
        crate::operation::describe_language_model::builders::DescribeLanguageModelOutputBuilder::default()
    }
}

/// A builder for [`DescribeLanguageModelOutput`](crate::operation::describe_language_model::DescribeLanguageModelOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLanguageModelOutputBuilder {
    pub(crate) language_model: ::std::option::Option<crate::types::LanguageModel>,
    _request_id: Option<String>,
}
impl DescribeLanguageModelOutputBuilder {
    /// <p>Provides information about the specified custom language model.</p>
    /// <p>This parameter also shows if the base language model you used to create your custom language model has been updated. If Amazon Transcribe has updated the base model, you can create a new custom language model using the updated base model.</p>
    /// <p>If you tried to create a new custom language model and the request wasn't successful, you can use this <code>DescribeLanguageModel</code> to help identify the reason for this failure.</p>
    pub fn language_model(mut self, input: crate::types::LanguageModel) -> Self {
        self.language_model = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about the specified custom language model.</p>
    /// <p>This parameter also shows if the base language model you used to create your custom language model has been updated. If Amazon Transcribe has updated the base model, you can create a new custom language model using the updated base model.</p>
    /// <p>If you tried to create a new custom language model and the request wasn't successful, you can use this <code>DescribeLanguageModel</code> to help identify the reason for this failure.</p>
    pub fn set_language_model(mut self, input: ::std::option::Option<crate::types::LanguageModel>) -> Self {
        self.language_model = input;
        self
    }
    /// <p>Provides information about the specified custom language model.</p>
    /// <p>This parameter also shows if the base language model you used to create your custom language model has been updated. If Amazon Transcribe has updated the base model, you can create a new custom language model using the updated base model.</p>
    /// <p>If you tried to create a new custom language model and the request wasn't successful, you can use this <code>DescribeLanguageModel</code> to help identify the reason for this failure.</p>
    pub fn get_language_model(&self) -> &::std::option::Option<crate::types::LanguageModel> {
        &self.language_model
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeLanguageModelOutput`](crate::operation::describe_language_model::DescribeLanguageModelOutput).
    pub fn build(self) -> crate::operation::describe_language_model::DescribeLanguageModelOutput {
        crate::operation::describe_language_model::DescribeLanguageModelOutput {
            language_model: self.language_model,
            _request_id: self._request_id,
        }
    }
}
