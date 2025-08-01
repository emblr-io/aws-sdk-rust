// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListActivatedRulesInRuleGroupInput {
    /// <p>The <code>RuleGroupId</code> of the <code>RuleGroup</code> for which you want to get a list of <code>ActivatedRule</code> objects.</p>
    pub rule_group_id: ::std::option::Option<::std::string::String>,
    /// <p>If you specify a value for <code>Limit</code> and you have more <code>ActivatedRules</code> than the value of <code>Limit</code>, AWS WAF returns a <code>NextMarker</code> value in the response that allows you to list another group of <code>ActivatedRules</code>. For the second and subsequent <code>ListActivatedRulesInRuleGroup</code> requests, specify the value of <code>NextMarker</code> from the previous response to get information about another batch of <code>ActivatedRules</code>.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the number of <code>ActivatedRules</code> that you want AWS WAF to return for this request. If you have more <code>ActivatedRules</code> than the number that you specify for <code>Limit</code>, the response includes a <code>NextMarker</code> value that you can use to get another batch of <code>ActivatedRules</code>.</p>
    pub limit: ::std::option::Option<i32>,
}
impl ListActivatedRulesInRuleGroupInput {
    /// <p>The <code>RuleGroupId</code> of the <code>RuleGroup</code> for which you want to get a list of <code>ActivatedRule</code> objects.</p>
    pub fn rule_group_id(&self) -> ::std::option::Option<&str> {
        self.rule_group_id.as_deref()
    }
    /// <p>If you specify a value for <code>Limit</code> and you have more <code>ActivatedRules</code> than the value of <code>Limit</code>, AWS WAF returns a <code>NextMarker</code> value in the response that allows you to list another group of <code>ActivatedRules</code>. For the second and subsequent <code>ListActivatedRulesInRuleGroup</code> requests, specify the value of <code>NextMarker</code> from the previous response to get information about another batch of <code>ActivatedRules</code>.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
    /// <p>Specifies the number of <code>ActivatedRules</code> that you want AWS WAF to return for this request. If you have more <code>ActivatedRules</code> than the number that you specify for <code>Limit</code>, the response includes a <code>NextMarker</code> value that you can use to get another batch of <code>ActivatedRules</code>.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
}
impl ListActivatedRulesInRuleGroupInput {
    /// Creates a new builder-style object to manufacture [`ListActivatedRulesInRuleGroupInput`](crate::operation::list_activated_rules_in_rule_group::ListActivatedRulesInRuleGroupInput).
    pub fn builder() -> crate::operation::list_activated_rules_in_rule_group::builders::ListActivatedRulesInRuleGroupInputBuilder {
        crate::operation::list_activated_rules_in_rule_group::builders::ListActivatedRulesInRuleGroupInputBuilder::default()
    }
}

/// A builder for [`ListActivatedRulesInRuleGroupInput`](crate::operation::list_activated_rules_in_rule_group::ListActivatedRulesInRuleGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListActivatedRulesInRuleGroupInputBuilder {
    pub(crate) rule_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
}
impl ListActivatedRulesInRuleGroupInputBuilder {
    /// <p>The <code>RuleGroupId</code> of the <code>RuleGroup</code> for which you want to get a list of <code>ActivatedRule</code> objects.</p>
    pub fn rule_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>RuleGroupId</code> of the <code>RuleGroup</code> for which you want to get a list of <code>ActivatedRule</code> objects.</p>
    pub fn set_rule_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_group_id = input;
        self
    }
    /// <p>The <code>RuleGroupId</code> of the <code>RuleGroup</code> for which you want to get a list of <code>ActivatedRule</code> objects.</p>
    pub fn get_rule_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_group_id
    }
    /// <p>If you specify a value for <code>Limit</code> and you have more <code>ActivatedRules</code> than the value of <code>Limit</code>, AWS WAF returns a <code>NextMarker</code> value in the response that allows you to list another group of <code>ActivatedRules</code>. For the second and subsequent <code>ListActivatedRulesInRuleGroup</code> requests, specify the value of <code>NextMarker</code> from the previous response to get information about another batch of <code>ActivatedRules</code>.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you specify a value for <code>Limit</code> and you have more <code>ActivatedRules</code> than the value of <code>Limit</code>, AWS WAF returns a <code>NextMarker</code> value in the response that allows you to list another group of <code>ActivatedRules</code>. For the second and subsequent <code>ListActivatedRulesInRuleGroup</code> requests, specify the value of <code>NextMarker</code> from the previous response to get information about another batch of <code>ActivatedRules</code>.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>If you specify a value for <code>Limit</code> and you have more <code>ActivatedRules</code> than the value of <code>Limit</code>, AWS WAF returns a <code>NextMarker</code> value in the response that allows you to list another group of <code>ActivatedRules</code>. For the second and subsequent <code>ListActivatedRulesInRuleGroup</code> requests, specify the value of <code>NextMarker</code> from the previous response to get information about another batch of <code>ActivatedRules</code>.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    /// <p>Specifies the number of <code>ActivatedRules</code> that you want AWS WAF to return for this request. If you have more <code>ActivatedRules</code> than the number that you specify for <code>Limit</code>, the response includes a <code>NextMarker</code> value that you can use to get another batch of <code>ActivatedRules</code>.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the number of <code>ActivatedRules</code> that you want AWS WAF to return for this request. If you have more <code>ActivatedRules</code> than the number that you specify for <code>Limit</code>, the response includes a <code>NextMarker</code> value that you can use to get another batch of <code>ActivatedRules</code>.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>Specifies the number of <code>ActivatedRules</code> that you want AWS WAF to return for this request. If you have more <code>ActivatedRules</code> than the number that you specify for <code>Limit</code>, the response includes a <code>NextMarker</code> value that you can use to get another batch of <code>ActivatedRules</code>.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// Consumes the builder and constructs a [`ListActivatedRulesInRuleGroupInput`](crate::operation::list_activated_rules_in_rule_group::ListActivatedRulesInRuleGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_activated_rules_in_rule_group::ListActivatedRulesInRuleGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_activated_rules_in_rule_group::ListActivatedRulesInRuleGroupInput {
            rule_group_id: self.rule_group_id,
            next_marker: self.next_marker,
            limit: self.limit,
        })
    }
}
