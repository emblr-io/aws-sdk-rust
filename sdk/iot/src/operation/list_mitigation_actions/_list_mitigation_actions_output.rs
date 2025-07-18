// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMitigationActionsOutput {
    /// <p>A set of actions that matched the specified filter criteria.</p>
    pub action_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::MitigationActionIdentifier>>,
    /// <p>The token for the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMitigationActionsOutput {
    /// <p>A set of actions that matched the specified filter criteria.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.action_identifiers.is_none()`.
    pub fn action_identifiers(&self) -> &[crate::types::MitigationActionIdentifier] {
        self.action_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListMitigationActionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListMitigationActionsOutput {
    /// Creates a new builder-style object to manufacture [`ListMitigationActionsOutput`](crate::operation::list_mitigation_actions::ListMitigationActionsOutput).
    pub fn builder() -> crate::operation::list_mitigation_actions::builders::ListMitigationActionsOutputBuilder {
        crate::operation::list_mitigation_actions::builders::ListMitigationActionsOutputBuilder::default()
    }
}

/// A builder for [`ListMitigationActionsOutput`](crate::operation::list_mitigation_actions::ListMitigationActionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMitigationActionsOutputBuilder {
    pub(crate) action_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::MitigationActionIdentifier>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMitigationActionsOutputBuilder {
    /// Appends an item to `action_identifiers`.
    ///
    /// To override the contents of this collection use [`set_action_identifiers`](Self::set_action_identifiers).
    ///
    /// <p>A set of actions that matched the specified filter criteria.</p>
    pub fn action_identifiers(mut self, input: crate::types::MitigationActionIdentifier) -> Self {
        let mut v = self.action_identifiers.unwrap_or_default();
        v.push(input);
        self.action_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>A set of actions that matched the specified filter criteria.</p>
    pub fn set_action_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MitigationActionIdentifier>>) -> Self {
        self.action_identifiers = input;
        self
    }
    /// <p>A set of actions that matched the specified filter criteria.</p>
    pub fn get_action_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MitigationActionIdentifier>> {
        &self.action_identifiers
    }
    /// <p>The token for the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results.</p>
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
    /// Consumes the builder and constructs a [`ListMitigationActionsOutput`](crate::operation::list_mitigation_actions::ListMitigationActionsOutput).
    pub fn build(self) -> crate::operation::list_mitigation_actions::ListMitigationActionsOutput {
        crate::operation::list_mitigation_actions::ListMitigationActionsOutput {
            action_identifiers: self.action_identifiers,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
