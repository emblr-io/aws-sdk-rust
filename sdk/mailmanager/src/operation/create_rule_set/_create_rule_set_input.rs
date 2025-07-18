// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRuleSetInput {
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>A user-friendly name for the rule set.</p>
    pub rule_set_name: ::std::option::Option<::std::string::String>,
    /// <p>Conditional rules that are evaluated for determining actions on email.</p>
    pub rules: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>,
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateRuleSetInput {
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>A user-friendly name for the rule set.</p>
    pub fn rule_set_name(&self) -> ::std::option::Option<&str> {
        self.rule_set_name.as_deref()
    }
    /// <p>Conditional rules that are evaluated for determining actions on email.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rules.is_none()`.
    pub fn rules(&self) -> &[crate::types::Rule] {
        self.rules.as_deref().unwrap_or_default()
    }
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateRuleSetInput {
    /// Creates a new builder-style object to manufacture [`CreateRuleSetInput`](crate::operation::create_rule_set::CreateRuleSetInput).
    pub fn builder() -> crate::operation::create_rule_set::builders::CreateRuleSetInputBuilder {
        crate::operation::create_rule_set::builders::CreateRuleSetInputBuilder::default()
    }
}

/// A builder for [`CreateRuleSetInput`](crate::operation::create_rule_set::CreateRuleSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRuleSetInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) rule_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) rules: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateRuleSetInputBuilder {
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique token that Amazon SES uses to recognize subsequent retries of the same request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>A user-friendly name for the rule set.</p>
    /// This field is required.
    pub fn rule_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A user-friendly name for the rule set.</p>
    pub fn set_rule_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_set_name = input;
        self
    }
    /// <p>A user-friendly name for the rule set.</p>
    pub fn get_rule_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_set_name
    }
    /// Appends an item to `rules`.
    ///
    /// To override the contents of this collection use [`set_rules`](Self::set_rules).
    ///
    /// <p>Conditional rules that are evaluated for determining actions on email.</p>
    pub fn rules(mut self, input: crate::types::Rule) -> Self {
        let mut v = self.rules.unwrap_or_default();
        v.push(input);
        self.rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>Conditional rules that are evaluated for determining actions on email.</p>
    pub fn set_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>) -> Self {
        self.rules = input;
        self
    }
    /// <p>Conditional rules that are evaluated for determining actions on email.</p>
    pub fn get_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Rule>> {
        &self.rules
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags used to organize, track, or control access for the resource. For example, { "tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateRuleSetInput`](crate::operation::create_rule_set::CreateRuleSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_rule_set::CreateRuleSetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_rule_set::CreateRuleSetInput {
            client_token: self.client_token,
            rule_set_name: self.rule_set_name,
            rules: self.rules,
            tags: self.tags,
        })
    }
}
