// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct RuleDetail {
    /// <p>The rule ID.</p>
    pub rule_id: ::std::option::Option<::std::string::String>,
    /// <p>The rule description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The detector for which the rule is associated.</p>
    pub detector_id: ::std::option::Option<::std::string::String>,
    /// <p>The rule version.</p>
    pub rule_version: ::std::option::Option<::std::string::String>,
    /// <p>The rule expression.</p>
    pub expression: ::std::option::Option<::std::string::String>,
    /// <p>The rule language.</p>
    pub language: ::std::option::Option<crate::types::Language>,
    /// <p>The rule outcomes.</p>
    pub outcomes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Timestamp of the last time the rule was updated.</p>
    pub last_updated_time: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of when the rule was created.</p>
    pub created_time: ::std::option::Option<::std::string::String>,
    /// <p>The rule ARN.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl RuleDetail {
    /// <p>The rule ID.</p>
    pub fn rule_id(&self) -> ::std::option::Option<&str> {
        self.rule_id.as_deref()
    }
    /// <p>The rule description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The detector for which the rule is associated.</p>
    pub fn detector_id(&self) -> ::std::option::Option<&str> {
        self.detector_id.as_deref()
    }
    /// <p>The rule version.</p>
    pub fn rule_version(&self) -> ::std::option::Option<&str> {
        self.rule_version.as_deref()
    }
    /// <p>The rule expression.</p>
    pub fn expression(&self) -> ::std::option::Option<&str> {
        self.expression.as_deref()
    }
    /// <p>The rule language.</p>
    pub fn language(&self) -> ::std::option::Option<&crate::types::Language> {
        self.language.as_ref()
    }
    /// <p>The rule outcomes.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.outcomes.is_none()`.
    pub fn outcomes(&self) -> &[::std::string::String] {
        self.outcomes.as_deref().unwrap_or_default()
    }
    /// <p>Timestamp of the last time the rule was updated.</p>
    pub fn last_updated_time(&self) -> ::std::option::Option<&str> {
        self.last_updated_time.as_deref()
    }
    /// <p>The timestamp of when the rule was created.</p>
    pub fn created_time(&self) -> ::std::option::Option<&str> {
        self.created_time.as_deref()
    }
    /// <p>The rule ARN.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl ::std::fmt::Debug for RuleDetail {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RuleDetail");
        formatter.field("rule_id", &self.rule_id);
        formatter.field("description", &self.description);
        formatter.field("detector_id", &self.detector_id);
        formatter.field("rule_version", &self.rule_version);
        formatter.field("expression", &"*** Sensitive Data Redacted ***");
        formatter.field("language", &self.language);
        formatter.field("outcomes", &self.outcomes);
        formatter.field("last_updated_time", &self.last_updated_time);
        formatter.field("created_time", &self.created_time);
        formatter.field("arn", &self.arn);
        formatter.finish()
    }
}
impl RuleDetail {
    /// Creates a new builder-style object to manufacture [`RuleDetail`](crate::types::RuleDetail).
    pub fn builder() -> crate::types::builders::RuleDetailBuilder {
        crate::types::builders::RuleDetailBuilder::default()
    }
}

/// A builder for [`RuleDetail`](crate::types::RuleDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct RuleDetailBuilder {
    pub(crate) rule_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) detector_id: ::std::option::Option<::std::string::String>,
    pub(crate) rule_version: ::std::option::Option<::std::string::String>,
    pub(crate) expression: ::std::option::Option<::std::string::String>,
    pub(crate) language: ::std::option::Option<crate::types::Language>,
    pub(crate) outcomes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) last_updated_time: ::std::option::Option<::std::string::String>,
    pub(crate) created_time: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl RuleDetailBuilder {
    /// <p>The rule ID.</p>
    pub fn rule_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The rule ID.</p>
    pub fn set_rule_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_id = input;
        self
    }
    /// <p>The rule ID.</p>
    pub fn get_rule_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_id
    }
    /// <p>The rule description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The rule description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The rule description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The detector for which the rule is associated.</p>
    pub fn detector_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detector_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The detector for which the rule is associated.</p>
    pub fn set_detector_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detector_id = input;
        self
    }
    /// <p>The detector for which the rule is associated.</p>
    pub fn get_detector_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.detector_id
    }
    /// <p>The rule version.</p>
    pub fn rule_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The rule version.</p>
    pub fn set_rule_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_version = input;
        self
    }
    /// <p>The rule version.</p>
    pub fn get_rule_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_version
    }
    /// <p>The rule expression.</p>
    pub fn expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The rule expression.</p>
    pub fn set_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expression = input;
        self
    }
    /// <p>The rule expression.</p>
    pub fn get_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.expression
    }
    /// <p>The rule language.</p>
    pub fn language(mut self, input: crate::types::Language) -> Self {
        self.language = ::std::option::Option::Some(input);
        self
    }
    /// <p>The rule language.</p>
    pub fn set_language(mut self, input: ::std::option::Option<crate::types::Language>) -> Self {
        self.language = input;
        self
    }
    /// <p>The rule language.</p>
    pub fn get_language(&self) -> &::std::option::Option<crate::types::Language> {
        &self.language
    }
    /// Appends an item to `outcomes`.
    ///
    /// To override the contents of this collection use [`set_outcomes`](Self::set_outcomes).
    ///
    /// <p>The rule outcomes.</p>
    pub fn outcomes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.outcomes.unwrap_or_default();
        v.push(input.into());
        self.outcomes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The rule outcomes.</p>
    pub fn set_outcomes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.outcomes = input;
        self
    }
    /// <p>The rule outcomes.</p>
    pub fn get_outcomes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.outcomes
    }
    /// <p>Timestamp of the last time the rule was updated.</p>
    pub fn last_updated_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_updated_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Timestamp of the last time the rule was updated.</p>
    pub fn set_last_updated_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_updated_time = input;
        self
    }
    /// <p>Timestamp of the last time the rule was updated.</p>
    pub fn get_last_updated_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_updated_time
    }
    /// <p>The timestamp of when the rule was created.</p>
    pub fn created_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The timestamp of when the rule was created.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>The timestamp of when the rule was created.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_time
    }
    /// <p>The rule ARN.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The rule ARN.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The rule ARN.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`RuleDetail`](crate::types::RuleDetail).
    pub fn build(self) -> crate::types::RuleDetail {
        crate::types::RuleDetail {
            rule_id: self.rule_id,
            description: self.description,
            detector_id: self.detector_id,
            rule_version: self.rule_version,
            expression: self.expression,
            language: self.language,
            outcomes: self.outcomes,
            last_updated_time: self.last_updated_time,
            created_time: self.created_time,
            arn: self.arn,
        }
    }
}
impl ::std::fmt::Debug for RuleDetailBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RuleDetailBuilder");
        formatter.field("rule_id", &self.rule_id);
        formatter.field("description", &self.description);
        formatter.field("detector_id", &self.detector_id);
        formatter.field("rule_version", &self.rule_version);
        formatter.field("expression", &"*** Sensitive Data Redacted ***");
        formatter.field("language", &self.language);
        formatter.field("outcomes", &self.outcomes);
        formatter.field("last_updated_time", &self.last_updated_time);
        formatter.field("created_time", &self.created_time);
        formatter.field("arn", &self.arn);
        formatter.finish()
    }
}
