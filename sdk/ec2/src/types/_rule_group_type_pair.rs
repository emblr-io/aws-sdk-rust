// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the type of a stateful rule group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuleGroupTypePair {
    /// <p>The ARN of the rule group.</p>
    pub rule_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The rule group type. The possible values are <code>Domain List</code> and <code>Suricata</code>.</p>
    pub rule_group_type: ::std::option::Option<::std::string::String>,
}
impl RuleGroupTypePair {
    /// <p>The ARN of the rule group.</p>
    pub fn rule_group_arn(&self) -> ::std::option::Option<&str> {
        self.rule_group_arn.as_deref()
    }
    /// <p>The rule group type. The possible values are <code>Domain List</code> and <code>Suricata</code>.</p>
    pub fn rule_group_type(&self) -> ::std::option::Option<&str> {
        self.rule_group_type.as_deref()
    }
}
impl RuleGroupTypePair {
    /// Creates a new builder-style object to manufacture [`RuleGroupTypePair`](crate::types::RuleGroupTypePair).
    pub fn builder() -> crate::types::builders::RuleGroupTypePairBuilder {
        crate::types::builders::RuleGroupTypePairBuilder::default()
    }
}

/// A builder for [`RuleGroupTypePair`](crate::types::RuleGroupTypePair).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuleGroupTypePairBuilder {
    pub(crate) rule_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) rule_group_type: ::std::option::Option<::std::string::String>,
}
impl RuleGroupTypePairBuilder {
    /// <p>The ARN of the rule group.</p>
    pub fn rule_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the rule group.</p>
    pub fn set_rule_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_group_arn = input;
        self
    }
    /// <p>The ARN of the rule group.</p>
    pub fn get_rule_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_group_arn
    }
    /// <p>The rule group type. The possible values are <code>Domain List</code> and <code>Suricata</code>.</p>
    pub fn rule_group_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_group_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The rule group type. The possible values are <code>Domain List</code> and <code>Suricata</code>.</p>
    pub fn set_rule_group_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_group_type = input;
        self
    }
    /// <p>The rule group type. The possible values are <code>Domain List</code> and <code>Suricata</code>.</p>
    pub fn get_rule_group_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_group_type
    }
    /// Consumes the builder and constructs a [`RuleGroupTypePair`](crate::types::RuleGroupTypePair).
    pub fn build(self) -> crate::types::RuleGroupTypePair {
        crate::types::RuleGroupTypePair {
            rule_group_arn: self.rule_group_arn,
            rule_group_type: self.rule_group_type,
        }
    }
}
