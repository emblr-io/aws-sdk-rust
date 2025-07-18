// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchRelevantContentOutput {
    /// <p>The list of relevant content items found.</p>
    pub relevant_content: ::std::option::Option<::std::vec::Vec<crate::types::RelevantContent>>,
    /// <p>The token to use to retrieve the next set of results, if there are any.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SearchRelevantContentOutput {
    /// <p>The list of relevant content items found.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.relevant_content.is_none()`.
    pub fn relevant_content(&self) -> &[crate::types::RelevantContent] {
        self.relevant_content.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next set of results, if there are any.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SearchRelevantContentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SearchRelevantContentOutput {
    /// Creates a new builder-style object to manufacture [`SearchRelevantContentOutput`](crate::operation::search_relevant_content::SearchRelevantContentOutput).
    pub fn builder() -> crate::operation::search_relevant_content::builders::SearchRelevantContentOutputBuilder {
        crate::operation::search_relevant_content::builders::SearchRelevantContentOutputBuilder::default()
    }
}

/// A builder for [`SearchRelevantContentOutput`](crate::operation::search_relevant_content::SearchRelevantContentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchRelevantContentOutputBuilder {
    pub(crate) relevant_content: ::std::option::Option<::std::vec::Vec<crate::types::RelevantContent>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SearchRelevantContentOutputBuilder {
    /// Appends an item to `relevant_content`.
    ///
    /// To override the contents of this collection use [`set_relevant_content`](Self::set_relevant_content).
    ///
    /// <p>The list of relevant content items found.</p>
    pub fn relevant_content(mut self, input: crate::types::RelevantContent) -> Self {
        let mut v = self.relevant_content.unwrap_or_default();
        v.push(input);
        self.relevant_content = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of relevant content items found.</p>
    pub fn set_relevant_content(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RelevantContent>>) -> Self {
        self.relevant_content = input;
        self
    }
    /// <p>The list of relevant content items found.</p>
    pub fn get_relevant_content(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RelevantContent>> {
        &self.relevant_content
    }
    /// <p>The token to use to retrieve the next set of results, if there are any.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next set of results, if there are any.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next set of results, if there are any.</p>
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
    /// Consumes the builder and constructs a [`SearchRelevantContentOutput`](crate::operation::search_relevant_content::SearchRelevantContentOutput).
    pub fn build(self) -> crate::operation::search_relevant_content::SearchRelevantContentOutput {
        crate::operation::search_relevant_content::SearchRelevantContentOutput {
            relevant_content: self.relevant_content,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
