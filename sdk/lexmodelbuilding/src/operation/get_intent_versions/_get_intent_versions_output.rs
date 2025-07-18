// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetIntentVersionsOutput {
    /// <p>An array of <code>IntentMetadata</code> objects, one for each numbered version of the intent plus one for the <code>$LATEST</code> version.</p>
    pub intents: ::std::option::Option<::std::vec::Vec<crate::types::IntentMetadata>>,
    /// <p>A pagination token for fetching the next page of intent versions. If the response to this call is truncated, Amazon Lex returns a pagination token in the response. To fetch the next page of versions, specify the pagination token in the next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetIntentVersionsOutput {
    /// <p>An array of <code>IntentMetadata</code> objects, one for each numbered version of the intent plus one for the <code>$LATEST</code> version.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.intents.is_none()`.
    pub fn intents(&self) -> &[crate::types::IntentMetadata] {
        self.intents.as_deref().unwrap_or_default()
    }
    /// <p>A pagination token for fetching the next page of intent versions. If the response to this call is truncated, Amazon Lex returns a pagination token in the response. To fetch the next page of versions, specify the pagination token in the next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetIntentVersionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetIntentVersionsOutput {
    /// Creates a new builder-style object to manufacture [`GetIntentVersionsOutput`](crate::operation::get_intent_versions::GetIntentVersionsOutput).
    pub fn builder() -> crate::operation::get_intent_versions::builders::GetIntentVersionsOutputBuilder {
        crate::operation::get_intent_versions::builders::GetIntentVersionsOutputBuilder::default()
    }
}

/// A builder for [`GetIntentVersionsOutput`](crate::operation::get_intent_versions::GetIntentVersionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetIntentVersionsOutputBuilder {
    pub(crate) intents: ::std::option::Option<::std::vec::Vec<crate::types::IntentMetadata>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetIntentVersionsOutputBuilder {
    /// Appends an item to `intents`.
    ///
    /// To override the contents of this collection use [`set_intents`](Self::set_intents).
    ///
    /// <p>An array of <code>IntentMetadata</code> objects, one for each numbered version of the intent plus one for the <code>$LATEST</code> version.</p>
    pub fn intents(mut self, input: crate::types::IntentMetadata) -> Self {
        let mut v = self.intents.unwrap_or_default();
        v.push(input);
        self.intents = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>IntentMetadata</code> objects, one for each numbered version of the intent plus one for the <code>$LATEST</code> version.</p>
    pub fn set_intents(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IntentMetadata>>) -> Self {
        self.intents = input;
        self
    }
    /// <p>An array of <code>IntentMetadata</code> objects, one for each numbered version of the intent plus one for the <code>$LATEST</code> version.</p>
    pub fn get_intents(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IntentMetadata>> {
        &self.intents
    }
    /// <p>A pagination token for fetching the next page of intent versions. If the response to this call is truncated, Amazon Lex returns a pagination token in the response. To fetch the next page of versions, specify the pagination token in the next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token for fetching the next page of intent versions. If the response to this call is truncated, Amazon Lex returns a pagination token in the response. To fetch the next page of versions, specify the pagination token in the next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token for fetching the next page of intent versions. If the response to this call is truncated, Amazon Lex returns a pagination token in the response. To fetch the next page of versions, specify the pagination token in the next request.</p>
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
    /// Consumes the builder and constructs a [`GetIntentVersionsOutput`](crate::operation::get_intent_versions::GetIntentVersionsOutput).
    pub fn build(self) -> crate::operation::get_intent_versions::GetIntentVersionsOutput {
        crate::operation::get_intent_versions::GetIntentVersionsOutput {
            intents: self.intents,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
