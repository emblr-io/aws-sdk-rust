// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListModelCardsOutput {
    /// <p>The summaries of the listed model cards.</p>
    pub model_card_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ModelCardSummary>>,
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model cards, use it in the subsequent request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListModelCardsOutput {
    /// <p>The summaries of the listed model cards.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.model_card_summaries.is_none()`.
    pub fn model_card_summaries(&self) -> &[crate::types::ModelCardSummary] {
        self.model_card_summaries.as_deref().unwrap_or_default()
    }
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model cards, use it in the subsequent request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListModelCardsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListModelCardsOutput {
    /// Creates a new builder-style object to manufacture [`ListModelCardsOutput`](crate::operation::list_model_cards::ListModelCardsOutput).
    pub fn builder() -> crate::operation::list_model_cards::builders::ListModelCardsOutputBuilder {
        crate::operation::list_model_cards::builders::ListModelCardsOutputBuilder::default()
    }
}

/// A builder for [`ListModelCardsOutput`](crate::operation::list_model_cards::ListModelCardsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListModelCardsOutputBuilder {
    pub(crate) model_card_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ModelCardSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListModelCardsOutputBuilder {
    /// Appends an item to `model_card_summaries`.
    ///
    /// To override the contents of this collection use [`set_model_card_summaries`](Self::set_model_card_summaries).
    ///
    /// <p>The summaries of the listed model cards.</p>
    pub fn model_card_summaries(mut self, input: crate::types::ModelCardSummary) -> Self {
        let mut v = self.model_card_summaries.unwrap_or_default();
        v.push(input);
        self.model_card_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>The summaries of the listed model cards.</p>
    pub fn set_model_card_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ModelCardSummary>>) -> Self {
        self.model_card_summaries = input;
        self
    }
    /// <p>The summaries of the listed model cards.</p>
    pub fn get_model_card_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ModelCardSummary>> {
        &self.model_card_summaries
    }
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model cards, use it in the subsequent request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model cards, use it in the subsequent request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model cards, use it in the subsequent request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListModelCardsOutput`](crate::operation::list_model_cards::ListModelCardsOutput).
    pub fn build(self) -> crate::operation::list_model_cards::ListModelCardsOutput {
        crate::operation::list_model_cards::ListModelCardsOutput {
            model_card_summaries: self.model_card_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
