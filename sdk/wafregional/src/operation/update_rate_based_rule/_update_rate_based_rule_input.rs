// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRateBasedRuleInput {
    /// <p>The <code>RuleId</code> of the <code>RateBasedRule</code> that you want to update. <code>RuleId</code> is returned by <code>CreateRateBasedRule</code> and by <code>ListRateBasedRules</code>.</p>
    pub rule_id: ::std::option::Option<::std::string::String>,
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub change_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of <code>RuleUpdate</code> objects that you want to insert into or delete from a <code>RateBasedRule</code>.</p>
    pub updates: ::std::option::Option<::std::vec::Vec<crate::types::RuleUpdate>>,
    /// <p>The maximum number of requests, which have an identical value in the field specified by the <code>RateKey</code>, allowed in a five-minute period. If the number of requests exceeds the <code>RateLimit</code> and the other predicates specified in the rule are also met, AWS WAF triggers the action that is specified for this rule.</p>
    pub rate_limit: ::std::option::Option<i64>,
}
impl UpdateRateBasedRuleInput {
    /// <p>The <code>RuleId</code> of the <code>RateBasedRule</code> that you want to update. <code>RuleId</code> is returned by <code>CreateRateBasedRule</code> and by <code>ListRateBasedRules</code>.</p>
    pub fn rule_id(&self) -> ::std::option::Option<&str> {
        self.rule_id.as_deref()
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn change_token(&self) -> ::std::option::Option<&str> {
        self.change_token.as_deref()
    }
    /// <p>An array of <code>RuleUpdate</code> objects that you want to insert into or delete from a <code>RateBasedRule</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.updates.is_none()`.
    pub fn updates(&self) -> &[crate::types::RuleUpdate] {
        self.updates.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of requests, which have an identical value in the field specified by the <code>RateKey</code>, allowed in a five-minute period. If the number of requests exceeds the <code>RateLimit</code> and the other predicates specified in the rule are also met, AWS WAF triggers the action that is specified for this rule.</p>
    pub fn rate_limit(&self) -> ::std::option::Option<i64> {
        self.rate_limit
    }
}
impl UpdateRateBasedRuleInput {
    /// Creates a new builder-style object to manufacture [`UpdateRateBasedRuleInput`](crate::operation::update_rate_based_rule::UpdateRateBasedRuleInput).
    pub fn builder() -> crate::operation::update_rate_based_rule::builders::UpdateRateBasedRuleInputBuilder {
        crate::operation::update_rate_based_rule::builders::UpdateRateBasedRuleInputBuilder::default()
    }
}

/// A builder for [`UpdateRateBasedRuleInput`](crate::operation::update_rate_based_rule::UpdateRateBasedRuleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRateBasedRuleInputBuilder {
    pub(crate) rule_id: ::std::option::Option<::std::string::String>,
    pub(crate) change_token: ::std::option::Option<::std::string::String>,
    pub(crate) updates: ::std::option::Option<::std::vec::Vec<crate::types::RuleUpdate>>,
    pub(crate) rate_limit: ::std::option::Option<i64>,
}
impl UpdateRateBasedRuleInputBuilder {
    /// <p>The <code>RuleId</code> of the <code>RateBasedRule</code> that you want to update. <code>RuleId</code> is returned by <code>CreateRateBasedRule</code> and by <code>ListRateBasedRules</code>.</p>
    /// This field is required.
    pub fn rule_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>RuleId</code> of the <code>RateBasedRule</code> that you want to update. <code>RuleId</code> is returned by <code>CreateRateBasedRule</code> and by <code>ListRateBasedRules</code>.</p>
    pub fn set_rule_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_id = input;
        self
    }
    /// <p>The <code>RuleId</code> of the <code>RateBasedRule</code> that you want to update. <code>RuleId</code> is returned by <code>CreateRateBasedRule</code> and by <code>ListRateBasedRules</code>.</p>
    pub fn get_rule_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_id
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    /// This field is required.
    pub fn change_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn set_change_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_token = input;
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn get_change_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_token
    }
    /// Appends an item to `updates`.
    ///
    /// To override the contents of this collection use [`set_updates`](Self::set_updates).
    ///
    /// <p>An array of <code>RuleUpdate</code> objects that you want to insert into or delete from a <code>RateBasedRule</code>.</p>
    pub fn updates(mut self, input: crate::types::RuleUpdate) -> Self {
        let mut v = self.updates.unwrap_or_default();
        v.push(input);
        self.updates = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>RuleUpdate</code> objects that you want to insert into or delete from a <code>RateBasedRule</code>.</p>
    pub fn set_updates(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RuleUpdate>>) -> Self {
        self.updates = input;
        self
    }
    /// <p>An array of <code>RuleUpdate</code> objects that you want to insert into or delete from a <code>RateBasedRule</code>.</p>
    pub fn get_updates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RuleUpdate>> {
        &self.updates
    }
    /// <p>The maximum number of requests, which have an identical value in the field specified by the <code>RateKey</code>, allowed in a five-minute period. If the number of requests exceeds the <code>RateLimit</code> and the other predicates specified in the rule are also met, AWS WAF triggers the action that is specified for this rule.</p>
    /// This field is required.
    pub fn rate_limit(mut self, input: i64) -> Self {
        self.rate_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of requests, which have an identical value in the field specified by the <code>RateKey</code>, allowed in a five-minute period. If the number of requests exceeds the <code>RateLimit</code> and the other predicates specified in the rule are also met, AWS WAF triggers the action that is specified for this rule.</p>
    pub fn set_rate_limit(mut self, input: ::std::option::Option<i64>) -> Self {
        self.rate_limit = input;
        self
    }
    /// <p>The maximum number of requests, which have an identical value in the field specified by the <code>RateKey</code>, allowed in a five-minute period. If the number of requests exceeds the <code>RateLimit</code> and the other predicates specified in the rule are also met, AWS WAF triggers the action that is specified for this rule.</p>
    pub fn get_rate_limit(&self) -> &::std::option::Option<i64> {
        &self.rate_limit
    }
    /// Consumes the builder and constructs a [`UpdateRateBasedRuleInput`](crate::operation::update_rate_based_rule::UpdateRateBasedRuleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_rate_based_rule::UpdateRateBasedRuleInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_rate_based_rule::UpdateRateBasedRuleInput {
            rule_id: self.rule_id,
            change_token: self.change_token,
            updates: self.updates,
            rate_limit: self.rate_limit,
        })
    }
}
