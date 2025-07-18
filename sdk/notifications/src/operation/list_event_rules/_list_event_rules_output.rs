// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEventRulesOutput {
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>EventRules</code>.</p>
    pub event_rules: ::std::vec::Vec<crate::types::EventRuleStructure>,
    _request_id: Option<String>,
}
impl ListEventRulesOutput {
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of <code>EventRules</code>.</p>
    pub fn event_rules(&self) -> &[crate::types::EventRuleStructure] {
        use std::ops::Deref;
        self.event_rules.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListEventRulesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListEventRulesOutput {
    /// Creates a new builder-style object to manufacture [`ListEventRulesOutput`](crate::operation::list_event_rules::ListEventRulesOutput).
    pub fn builder() -> crate::operation::list_event_rules::builders::ListEventRulesOutputBuilder {
        crate::operation::list_event_rules::builders::ListEventRulesOutputBuilder::default()
    }
}

/// A builder for [`ListEventRulesOutput`](crate::operation::list_event_rules::ListEventRulesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEventRulesOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) event_rules: ::std::option::Option<::std::vec::Vec<crate::types::EventRuleStructure>>,
    _request_id: Option<String>,
}
impl ListEventRulesOutputBuilder {
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `event_rules`.
    ///
    /// To override the contents of this collection use [`set_event_rules`](Self::set_event_rules).
    ///
    /// <p>A list of <code>EventRules</code>.</p>
    pub fn event_rules(mut self, input: crate::types::EventRuleStructure) -> Self {
        let mut v = self.event_rules.unwrap_or_default();
        v.push(input);
        self.event_rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>EventRules</code>.</p>
    pub fn set_event_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EventRuleStructure>>) -> Self {
        self.event_rules = input;
        self
    }
    /// <p>A list of <code>EventRules</code>.</p>
    pub fn get_event_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EventRuleStructure>> {
        &self.event_rules
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListEventRulesOutput`](crate::operation::list_event_rules::ListEventRulesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`event_rules`](crate::operation::list_event_rules::builders::ListEventRulesOutputBuilder::event_rules)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_event_rules::ListEventRulesOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_event_rules::ListEventRulesOutput {
            next_token: self.next_token,
            event_rules: self.event_rules.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "event_rules",
                    "event_rules was not specified but it is required when building ListEventRulesOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
