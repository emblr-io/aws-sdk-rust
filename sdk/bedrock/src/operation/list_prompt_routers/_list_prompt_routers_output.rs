// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPromptRoutersOutput {
    /// <p>A list of prompt router summaries.</p>
    pub prompt_router_summaries: ::std::option::Option<::std::vec::Vec<crate::types::PromptRouterSummary>>,
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPromptRoutersOutput {
    /// <p>A list of prompt router summaries.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.prompt_router_summaries.is_none()`.
    pub fn prompt_router_summaries(&self) -> &[crate::types::PromptRouterSummary] {
        self.prompt_router_summaries.as_deref().unwrap_or_default()
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPromptRoutersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPromptRoutersOutput {
    /// Creates a new builder-style object to manufacture [`ListPromptRoutersOutput`](crate::operation::list_prompt_routers::ListPromptRoutersOutput).
    pub fn builder() -> crate::operation::list_prompt_routers::builders::ListPromptRoutersOutputBuilder {
        crate::operation::list_prompt_routers::builders::ListPromptRoutersOutputBuilder::default()
    }
}

/// A builder for [`ListPromptRoutersOutput`](crate::operation::list_prompt_routers::ListPromptRoutersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPromptRoutersOutputBuilder {
    pub(crate) prompt_router_summaries: ::std::option::Option<::std::vec::Vec<crate::types::PromptRouterSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPromptRoutersOutputBuilder {
    /// Appends an item to `prompt_router_summaries`.
    ///
    /// To override the contents of this collection use [`set_prompt_router_summaries`](Self::set_prompt_router_summaries).
    ///
    /// <p>A list of prompt router summaries.</p>
    pub fn prompt_router_summaries(mut self, input: crate::types::PromptRouterSummary) -> Self {
        let mut v = self.prompt_router_summaries.unwrap_or_default();
        v.push(input);
        self.prompt_router_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of prompt router summaries.</p>
    pub fn set_prompt_router_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PromptRouterSummary>>) -> Self {
        self.prompt_router_summaries = input;
        self
    }
    /// <p>A list of prompt router summaries.</p>
    pub fn get_prompt_router_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PromptRouterSummary>> {
        &self.prompt_router_summaries
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
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
    /// Consumes the builder and constructs a [`ListPromptRoutersOutput`](crate::operation::list_prompt_routers::ListPromptRoutersOutput).
    pub fn build(self) -> crate::operation::list_prompt_routers::ListPromptRoutersOutput {
        crate::operation::list_prompt_routers::ListPromptRoutersOutput {
            prompt_router_summaries: self.prompt_router_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
