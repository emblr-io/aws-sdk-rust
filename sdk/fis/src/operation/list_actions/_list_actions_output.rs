// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListActionsOutput {
    /// <p>The actions.</p>
    pub actions: ::std::option::Option<::std::vec::Vec<crate::types::ActionSummary>>,
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListActionsOutput {
    /// <p>The actions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actions.is_none()`.
    pub fn actions(&self) -> &[crate::types::ActionSummary] {
        self.actions.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListActionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListActionsOutput {
    /// Creates a new builder-style object to manufacture [`ListActionsOutput`](crate::operation::list_actions::ListActionsOutput).
    pub fn builder() -> crate::operation::list_actions::builders::ListActionsOutputBuilder {
        crate::operation::list_actions::builders::ListActionsOutputBuilder::default()
    }
}

/// A builder for [`ListActionsOutput`](crate::operation::list_actions::ListActionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListActionsOutputBuilder {
    pub(crate) actions: ::std::option::Option<::std::vec::Vec<crate::types::ActionSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListActionsOutputBuilder {
    /// Appends an item to `actions`.
    ///
    /// To override the contents of this collection use [`set_actions`](Self::set_actions).
    ///
    /// <p>The actions.</p>
    pub fn actions(mut self, input: crate::types::ActionSummary) -> Self {
        let mut v = self.actions.unwrap_or_default();
        v.push(input);
        self.actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The actions.</p>
    pub fn set_actions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ActionSummary>>) -> Self {
        self.actions = input;
        self
    }
    /// <p>The actions.</p>
    pub fn get_actions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ActionSummary>> {
        &self.actions
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`ListActionsOutput`](crate::operation::list_actions::ListActionsOutput).
    pub fn build(self) -> crate::operation::list_actions::ListActionsOutput {
        crate::operation::list_actions::ListActionsOutput {
            actions: self.actions,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
