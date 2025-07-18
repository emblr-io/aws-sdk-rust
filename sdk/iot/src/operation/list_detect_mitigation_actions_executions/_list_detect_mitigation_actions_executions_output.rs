// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDetectMitigationActionsExecutionsOutput {
    /// <p>List of actions executions.</p>
    pub actions_executions: ::std::option::Option<::std::vec::Vec<crate::types::DetectMitigationActionExecution>>,
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> if there are no additional results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDetectMitigationActionsExecutionsOutput {
    /// <p>List of actions executions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actions_executions.is_none()`.
    pub fn actions_executions(&self) -> &[crate::types::DetectMitigationActionExecution] {
        self.actions_executions.as_deref().unwrap_or_default()
    }
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> if there are no additional results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDetectMitigationActionsExecutionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDetectMitigationActionsExecutionsOutput {
    /// Creates a new builder-style object to manufacture [`ListDetectMitigationActionsExecutionsOutput`](crate::operation::list_detect_mitigation_actions_executions::ListDetectMitigationActionsExecutionsOutput).
    pub fn builder() -> crate::operation::list_detect_mitigation_actions_executions::builders::ListDetectMitigationActionsExecutionsOutputBuilder {
        crate::operation::list_detect_mitigation_actions_executions::builders::ListDetectMitigationActionsExecutionsOutputBuilder::default()
    }
}

/// A builder for [`ListDetectMitigationActionsExecutionsOutput`](crate::operation::list_detect_mitigation_actions_executions::ListDetectMitigationActionsExecutionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDetectMitigationActionsExecutionsOutputBuilder {
    pub(crate) actions_executions: ::std::option::Option<::std::vec::Vec<crate::types::DetectMitigationActionExecution>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDetectMitigationActionsExecutionsOutputBuilder {
    /// Appends an item to `actions_executions`.
    ///
    /// To override the contents of this collection use [`set_actions_executions`](Self::set_actions_executions).
    ///
    /// <p>List of actions executions.</p>
    pub fn actions_executions(mut self, input: crate::types::DetectMitigationActionExecution) -> Self {
        let mut v = self.actions_executions.unwrap_or_default();
        v.push(input);
        self.actions_executions = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of actions executions.</p>
    pub fn set_actions_executions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DetectMitigationActionExecution>>) -> Self {
        self.actions_executions = input;
        self
    }
    /// <p>List of actions executions.</p>
    pub fn get_actions_executions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DetectMitigationActionExecution>> {
        &self.actions_executions
    }
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> if there are no additional results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> if there are no additional results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that can be used to retrieve the next set of results, or <code>null</code> if there are no additional results.</p>
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
    /// Consumes the builder and constructs a [`ListDetectMitigationActionsExecutionsOutput`](crate::operation::list_detect_mitigation_actions_executions::ListDetectMitigationActionsExecutionsOutput).
    pub fn build(self) -> crate::operation::list_detect_mitigation_actions_executions::ListDetectMitigationActionsExecutionsOutput {
        crate::operation::list_detect_mitigation_actions_executions::ListDetectMitigationActionsExecutionsOutput {
            actions_executions: self.actions_executions,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
