// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a successful Rule request, with status for an individual rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuleResult {
    /// <p>The time the resource was last checked for readiness, in ISO-8601 format, UTC.</p>
    pub last_checked_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Details about the resource's readiness.</p>
    pub messages: ::std::option::Option<::std::vec::Vec<crate::types::Message>>,
    /// <p>The readiness at rule level.</p>
    pub readiness: ::std::option::Option<crate::types::Readiness>,
    /// <p>The identifier of the rule.</p>
    pub rule_id: ::std::option::Option<::std::string::String>,
}
impl RuleResult {
    /// <p>The time the resource was last checked for readiness, in ISO-8601 format, UTC.</p>
    pub fn last_checked_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_checked_timestamp.as_ref()
    }
    /// <p>Details about the resource's readiness.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.messages.is_none()`.
    pub fn messages(&self) -> &[crate::types::Message] {
        self.messages.as_deref().unwrap_or_default()
    }
    /// <p>The readiness at rule level.</p>
    pub fn readiness(&self) -> ::std::option::Option<&crate::types::Readiness> {
        self.readiness.as_ref()
    }
    /// <p>The identifier of the rule.</p>
    pub fn rule_id(&self) -> ::std::option::Option<&str> {
        self.rule_id.as_deref()
    }
}
impl RuleResult {
    /// Creates a new builder-style object to manufacture [`RuleResult`](crate::types::RuleResult).
    pub fn builder() -> crate::types::builders::RuleResultBuilder {
        crate::types::builders::RuleResultBuilder::default()
    }
}

/// A builder for [`RuleResult`](crate::types::RuleResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuleResultBuilder {
    pub(crate) last_checked_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) messages: ::std::option::Option<::std::vec::Vec<crate::types::Message>>,
    pub(crate) readiness: ::std::option::Option<crate::types::Readiness>,
    pub(crate) rule_id: ::std::option::Option<::std::string::String>,
}
impl RuleResultBuilder {
    /// <p>The time the resource was last checked for readiness, in ISO-8601 format, UTC.</p>
    /// This field is required.
    pub fn last_checked_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_checked_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the resource was last checked for readiness, in ISO-8601 format, UTC.</p>
    pub fn set_last_checked_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_checked_timestamp = input;
        self
    }
    /// <p>The time the resource was last checked for readiness, in ISO-8601 format, UTC.</p>
    pub fn get_last_checked_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_checked_timestamp
    }
    /// Appends an item to `messages`.
    ///
    /// To override the contents of this collection use [`set_messages`](Self::set_messages).
    ///
    /// <p>Details about the resource's readiness.</p>
    pub fn messages(mut self, input: crate::types::Message) -> Self {
        let mut v = self.messages.unwrap_or_default();
        v.push(input);
        self.messages = ::std::option::Option::Some(v);
        self
    }
    /// <p>Details about the resource's readiness.</p>
    pub fn set_messages(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Message>>) -> Self {
        self.messages = input;
        self
    }
    /// <p>Details about the resource's readiness.</p>
    pub fn get_messages(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Message>> {
        &self.messages
    }
    /// <p>The readiness at rule level.</p>
    /// This field is required.
    pub fn readiness(mut self, input: crate::types::Readiness) -> Self {
        self.readiness = ::std::option::Option::Some(input);
        self
    }
    /// <p>The readiness at rule level.</p>
    pub fn set_readiness(mut self, input: ::std::option::Option<crate::types::Readiness>) -> Self {
        self.readiness = input;
        self
    }
    /// <p>The readiness at rule level.</p>
    pub fn get_readiness(&self) -> &::std::option::Option<crate::types::Readiness> {
        &self.readiness
    }
    /// <p>The identifier of the rule.</p>
    /// This field is required.
    pub fn rule_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the rule.</p>
    pub fn set_rule_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_id = input;
        self
    }
    /// <p>The identifier of the rule.</p>
    pub fn get_rule_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_id
    }
    /// Consumes the builder and constructs a [`RuleResult`](crate::types::RuleResult).
    pub fn build(self) -> crate::types::RuleResult {
        crate::types::RuleResult {
            last_checked_timestamp: self.last_checked_timestamp,
            messages: self.messages,
            readiness: self.readiness,
            rule_id: self.rule_id,
        }
    }
}
