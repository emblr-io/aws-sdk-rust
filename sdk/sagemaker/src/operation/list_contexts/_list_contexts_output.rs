// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListContextsOutput {
    /// <p>A list of contexts and their properties.</p>
    pub context_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ContextSummary>>,
    /// <p>A token for getting the next set of contexts, if there are any.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListContextsOutput {
    /// <p>A list of contexts and their properties.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.context_summaries.is_none()`.
    pub fn context_summaries(&self) -> &[crate::types::ContextSummary] {
        self.context_summaries.as_deref().unwrap_or_default()
    }
    /// <p>A token for getting the next set of contexts, if there are any.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListContextsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListContextsOutput {
    /// Creates a new builder-style object to manufacture [`ListContextsOutput`](crate::operation::list_contexts::ListContextsOutput).
    pub fn builder() -> crate::operation::list_contexts::builders::ListContextsOutputBuilder {
        crate::operation::list_contexts::builders::ListContextsOutputBuilder::default()
    }
}

/// A builder for [`ListContextsOutput`](crate::operation::list_contexts::ListContextsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListContextsOutputBuilder {
    pub(crate) context_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ContextSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListContextsOutputBuilder {
    /// Appends an item to `context_summaries`.
    ///
    /// To override the contents of this collection use [`set_context_summaries`](Self::set_context_summaries).
    ///
    /// <p>A list of contexts and their properties.</p>
    pub fn context_summaries(mut self, input: crate::types::ContextSummary) -> Self {
        let mut v = self.context_summaries.unwrap_or_default();
        v.push(input);
        self.context_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of contexts and their properties.</p>
    pub fn set_context_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ContextSummary>>) -> Self {
        self.context_summaries = input;
        self
    }
    /// <p>A list of contexts and their properties.</p>
    pub fn get_context_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ContextSummary>> {
        &self.context_summaries
    }
    /// <p>A token for getting the next set of contexts, if there are any.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token for getting the next set of contexts, if there are any.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token for getting the next set of contexts, if there are any.</p>
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
    /// Consumes the builder and constructs a [`ListContextsOutput`](crate::operation::list_contexts::ListContextsOutput).
    pub fn build(self) -> crate::operation::list_contexts::ListContextsOutput {
        crate::operation::list_contexts::ListContextsOutput {
            context_summaries: self.context_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
