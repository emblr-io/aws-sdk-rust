// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>High-level information about a <code>Rule</code>, returned by operations like <code>DescribeManagedRuleGroup</code>. This provides information like the ID, that you can use to retrieve and manage a <code>RuleGroup</code>, and the ARN, that you provide to the <code>RuleGroupReferenceStatement</code> to use the rule group in a <code>Rule</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuleSummary {
    /// <p>The name of the rule.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The action that WAF should take on a web request when it matches a rule's statement. Settings at the web ACL level can override the rule action setting.</p>
    pub action: ::std::option::Option<crate::types::RuleAction>,
}
impl RuleSummary {
    /// <p>The name of the rule.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The action that WAF should take on a web request when it matches a rule's statement. Settings at the web ACL level can override the rule action setting.</p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::RuleAction> {
        self.action.as_ref()
    }
}
impl RuleSummary {
    /// Creates a new builder-style object to manufacture [`RuleSummary`](crate::types::RuleSummary).
    pub fn builder() -> crate::types::builders::RuleSummaryBuilder {
        crate::types::builders::RuleSummaryBuilder::default()
    }
}

/// A builder for [`RuleSummary`](crate::types::RuleSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuleSummaryBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) action: ::std::option::Option<crate::types::RuleAction>,
}
impl RuleSummaryBuilder {
    /// <p>The name of the rule.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the rule.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the rule.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The action that WAF should take on a web request when it matches a rule's statement. Settings at the web ACL level can override the rule action setting.</p>
    pub fn action(mut self, input: crate::types::RuleAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action that WAF should take on a web request when it matches a rule's statement. Settings at the web ACL level can override the rule action setting.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::RuleAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>The action that WAF should take on a web request when it matches a rule's statement. Settings at the web ACL level can override the rule action setting.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::RuleAction> {
        &self.action
    }
    /// Consumes the builder and constructs a [`RuleSummary`](crate::types::RuleSummary).
    pub fn build(self) -> crate::types::RuleSummary {
        crate::types::RuleSummary {
            name: self.name,
            action: self.action,
        }
    }
}
