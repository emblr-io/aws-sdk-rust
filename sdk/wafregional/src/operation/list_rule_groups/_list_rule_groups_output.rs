// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRuleGroupsOutput {
    /// <p>If you have more <code>RuleGroups</code> than the number that you specified for <code>Limit</code> in the request, the response includes a <code>NextMarker</code> value. To list more <code>RuleGroups</code>, submit another <code>ListRuleGroups</code> request, and specify the <code>NextMarker</code> value from the response in the <code>NextMarker</code> value in the next request.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    /// <p>An array of <code>RuleGroup</code> objects.</p>
    pub rule_groups: ::std::option::Option<::std::vec::Vec<crate::types::RuleGroupSummary>>,
    _request_id: Option<String>,
}
impl ListRuleGroupsOutput {
    /// <p>If you have more <code>RuleGroups</code> than the number that you specified for <code>Limit</code> in the request, the response includes a <code>NextMarker</code> value. To list more <code>RuleGroups</code>, submit another <code>ListRuleGroups</code> request, and specify the <code>NextMarker</code> value from the response in the <code>NextMarker</code> value in the next request.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
    /// <p>An array of <code>RuleGroup</code> objects.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rule_groups.is_none()`.
    pub fn rule_groups(&self) -> &[crate::types::RuleGroupSummary] {
        self.rule_groups.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListRuleGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRuleGroupsOutput {
    /// Creates a new builder-style object to manufacture [`ListRuleGroupsOutput`](crate::operation::list_rule_groups::ListRuleGroupsOutput).
    pub fn builder() -> crate::operation::list_rule_groups::builders::ListRuleGroupsOutputBuilder {
        crate::operation::list_rule_groups::builders::ListRuleGroupsOutputBuilder::default()
    }
}

/// A builder for [`ListRuleGroupsOutput`](crate::operation::list_rule_groups::ListRuleGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRuleGroupsOutputBuilder {
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    pub(crate) rule_groups: ::std::option::Option<::std::vec::Vec<crate::types::RuleGroupSummary>>,
    _request_id: Option<String>,
}
impl ListRuleGroupsOutputBuilder {
    /// <p>If you have more <code>RuleGroups</code> than the number that you specified for <code>Limit</code> in the request, the response includes a <code>NextMarker</code> value. To list more <code>RuleGroups</code>, submit another <code>ListRuleGroups</code> request, and specify the <code>NextMarker</code> value from the response in the <code>NextMarker</code> value in the next request.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you have more <code>RuleGroups</code> than the number that you specified for <code>Limit</code> in the request, the response includes a <code>NextMarker</code> value. To list more <code>RuleGroups</code>, submit another <code>ListRuleGroups</code> request, and specify the <code>NextMarker</code> value from the response in the <code>NextMarker</code> value in the next request.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>If you have more <code>RuleGroups</code> than the number that you specified for <code>Limit</code> in the request, the response includes a <code>NextMarker</code> value. To list more <code>RuleGroups</code>, submit another <code>ListRuleGroups</code> request, and specify the <code>NextMarker</code> value from the response in the <code>NextMarker</code> value in the next request.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    /// Appends an item to `rule_groups`.
    ///
    /// To override the contents of this collection use [`set_rule_groups`](Self::set_rule_groups).
    ///
    /// <p>An array of <code>RuleGroup</code> objects.</p>
    pub fn rule_groups(mut self, input: crate::types::RuleGroupSummary) -> Self {
        let mut v = self.rule_groups.unwrap_or_default();
        v.push(input);
        self.rule_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>RuleGroup</code> objects.</p>
    pub fn set_rule_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RuleGroupSummary>>) -> Self {
        self.rule_groups = input;
        self
    }
    /// <p>An array of <code>RuleGroup</code> objects.</p>
    pub fn get_rule_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RuleGroupSummary>> {
        &self.rule_groups
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListRuleGroupsOutput`](crate::operation::list_rule_groups::ListRuleGroupsOutput).
    pub fn build(self) -> crate::operation::list_rule_groups::ListRuleGroupsOutput {
        crate::operation::list_rule_groups::ListRuleGroupsOutput {
            next_marker: self.next_marker,
            rule_groups: self.rule_groups,
            _request_id: self._request_id,
        }
    }
}
