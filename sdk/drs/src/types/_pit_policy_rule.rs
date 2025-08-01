// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A rule in the Point in Time (PIT) policy representing when to take snapshots and how long to retain them for.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PitPolicyRule {
    /// <p>The ID of the rule.</p>
    pub rule_id: i64,
    /// <p>The units used to measure the interval and retentionDuration.</p>
    pub units: crate::types::PitPolicyRuleUnits,
    /// <p>How often, in the chosen units, a snapshot should be taken.</p>
    pub interval: i32,
    /// <p>The duration to retain a snapshot for, in the chosen units.</p>
    pub retention_duration: i32,
    /// <p>Whether this rule is enabled or not.</p>
    pub enabled: ::std::option::Option<bool>,
}
impl PitPolicyRule {
    /// <p>The ID of the rule.</p>
    pub fn rule_id(&self) -> i64 {
        self.rule_id
    }
    /// <p>The units used to measure the interval and retentionDuration.</p>
    pub fn units(&self) -> &crate::types::PitPolicyRuleUnits {
        &self.units
    }
    /// <p>How often, in the chosen units, a snapshot should be taken.</p>
    pub fn interval(&self) -> i32 {
        self.interval
    }
    /// <p>The duration to retain a snapshot for, in the chosen units.</p>
    pub fn retention_duration(&self) -> i32 {
        self.retention_duration
    }
    /// <p>Whether this rule is enabled or not.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
}
impl PitPolicyRule {
    /// Creates a new builder-style object to manufacture [`PitPolicyRule`](crate::types::PitPolicyRule).
    pub fn builder() -> crate::types::builders::PitPolicyRuleBuilder {
        crate::types::builders::PitPolicyRuleBuilder::default()
    }
}

/// A builder for [`PitPolicyRule`](crate::types::PitPolicyRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PitPolicyRuleBuilder {
    pub(crate) rule_id: ::std::option::Option<i64>,
    pub(crate) units: ::std::option::Option<crate::types::PitPolicyRuleUnits>,
    pub(crate) interval: ::std::option::Option<i32>,
    pub(crate) retention_duration: ::std::option::Option<i32>,
    pub(crate) enabled: ::std::option::Option<bool>,
}
impl PitPolicyRuleBuilder {
    /// <p>The ID of the rule.</p>
    pub fn rule_id(mut self, input: i64) -> Self {
        self.rule_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the rule.</p>
    pub fn set_rule_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.rule_id = input;
        self
    }
    /// <p>The ID of the rule.</p>
    pub fn get_rule_id(&self) -> &::std::option::Option<i64> {
        &self.rule_id
    }
    /// <p>The units used to measure the interval and retentionDuration.</p>
    /// This field is required.
    pub fn units(mut self, input: crate::types::PitPolicyRuleUnits) -> Self {
        self.units = ::std::option::Option::Some(input);
        self
    }
    /// <p>The units used to measure the interval and retentionDuration.</p>
    pub fn set_units(mut self, input: ::std::option::Option<crate::types::PitPolicyRuleUnits>) -> Self {
        self.units = input;
        self
    }
    /// <p>The units used to measure the interval and retentionDuration.</p>
    pub fn get_units(&self) -> &::std::option::Option<crate::types::PitPolicyRuleUnits> {
        &self.units
    }
    /// <p>How often, in the chosen units, a snapshot should be taken.</p>
    /// This field is required.
    pub fn interval(mut self, input: i32) -> Self {
        self.interval = ::std::option::Option::Some(input);
        self
    }
    /// <p>How often, in the chosen units, a snapshot should be taken.</p>
    pub fn set_interval(mut self, input: ::std::option::Option<i32>) -> Self {
        self.interval = input;
        self
    }
    /// <p>How often, in the chosen units, a snapshot should be taken.</p>
    pub fn get_interval(&self) -> &::std::option::Option<i32> {
        &self.interval
    }
    /// <p>The duration to retain a snapshot for, in the chosen units.</p>
    /// This field is required.
    pub fn retention_duration(mut self, input: i32) -> Self {
        self.retention_duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration to retain a snapshot for, in the chosen units.</p>
    pub fn set_retention_duration(mut self, input: ::std::option::Option<i32>) -> Self {
        self.retention_duration = input;
        self
    }
    /// <p>The duration to retain a snapshot for, in the chosen units.</p>
    pub fn get_retention_duration(&self) -> &::std::option::Option<i32> {
        &self.retention_duration
    }
    /// <p>Whether this rule is enabled or not.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether this rule is enabled or not.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Whether this rule is enabled or not.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Consumes the builder and constructs a [`PitPolicyRule`](crate::types::PitPolicyRule).
    /// This method will fail if any of the following fields are not set:
    /// - [`units`](crate::types::builders::PitPolicyRuleBuilder::units)
    /// - [`interval`](crate::types::builders::PitPolicyRuleBuilder::interval)
    /// - [`retention_duration`](crate::types::builders::PitPolicyRuleBuilder::retention_duration)
    pub fn build(self) -> ::std::result::Result<crate::types::PitPolicyRule, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PitPolicyRule {
            rule_id: self.rule_id.unwrap_or_default(),
            units: self.units.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "units",
                    "units was not specified but it is required when building PitPolicyRule",
                )
            })?,
            interval: self.interval.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "interval",
                    "interval was not specified but it is required when building PitPolicyRule",
                )
            })?,
            retention_duration: self.retention_duration.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "retention_duration",
                    "retention_duration was not specified but it is required when building PitPolicyRule",
                )
            })?,
            enabled: self.enabled,
        })
    }
}
