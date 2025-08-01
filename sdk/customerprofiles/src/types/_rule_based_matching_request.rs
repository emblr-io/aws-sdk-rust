// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request to enable the rule-based matching.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuleBasedMatchingRequest {
    /// <p>The flag that enables the rule-based matching process of duplicate profiles.</p>
    pub enabled: bool,
    /// <p>Configures how the rule-based matching process should match profiles. You can have up to 15 <code>MatchingRule</code> in the <code>MatchingRules</code>.</p>
    pub matching_rules: ::std::option::Option<::std::vec::Vec<crate::types::MatchingRule>>,
    /// <p><a href="https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_MatchingRule.html">MatchingRule</a></p>
    pub max_allowed_rule_level_for_merging: ::std::option::Option<i32>,
    /// <p>Indicates the maximum allowed rule level.</p>
    pub max_allowed_rule_level_for_matching: ::std::option::Option<i32>,
    /// <p>Configures information about the <code>AttributeTypesSelector</code> where the rule-based identity resolution uses to match profiles.</p>
    pub attribute_types_selector: ::std::option::Option<crate::types::AttributeTypesSelector>,
    /// <p>How the auto-merging process should resolve conflicts between different profiles.</p>
    pub conflict_resolution: ::std::option::Option<crate::types::ConflictResolution>,
    /// <p>Configuration information about the S3 bucket where Identity Resolution Jobs writes result files.</p><note>
    /// <p>You need to give Customer Profiles service principal write permission to your S3 bucket. Otherwise, you'll get an exception in the API response. For an example policy, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/cross-service-confused-deputy-prevention.html#customer-profiles-cross-service">Amazon Connect Customer Profiles cross-service confused deputy prevention</a>.</p>
    /// </note>
    pub exporting_config: ::std::option::Option<crate::types::ExportingConfig>,
}
impl RuleBasedMatchingRequest {
    /// <p>The flag that enables the rule-based matching process of duplicate profiles.</p>
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// <p>Configures how the rule-based matching process should match profiles. You can have up to 15 <code>MatchingRule</code> in the <code>MatchingRules</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.matching_rules.is_none()`.
    pub fn matching_rules(&self) -> &[crate::types::MatchingRule] {
        self.matching_rules.as_deref().unwrap_or_default()
    }
    /// <p><a href="https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_MatchingRule.html">MatchingRule</a></p>
    pub fn max_allowed_rule_level_for_merging(&self) -> ::std::option::Option<i32> {
        self.max_allowed_rule_level_for_merging
    }
    /// <p>Indicates the maximum allowed rule level.</p>
    pub fn max_allowed_rule_level_for_matching(&self) -> ::std::option::Option<i32> {
        self.max_allowed_rule_level_for_matching
    }
    /// <p>Configures information about the <code>AttributeTypesSelector</code> where the rule-based identity resolution uses to match profiles.</p>
    pub fn attribute_types_selector(&self) -> ::std::option::Option<&crate::types::AttributeTypesSelector> {
        self.attribute_types_selector.as_ref()
    }
    /// <p>How the auto-merging process should resolve conflicts between different profiles.</p>
    pub fn conflict_resolution(&self) -> ::std::option::Option<&crate::types::ConflictResolution> {
        self.conflict_resolution.as_ref()
    }
    /// <p>Configuration information about the S3 bucket where Identity Resolution Jobs writes result files.</p><note>
    /// <p>You need to give Customer Profiles service principal write permission to your S3 bucket. Otherwise, you'll get an exception in the API response. For an example policy, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/cross-service-confused-deputy-prevention.html#customer-profiles-cross-service">Amazon Connect Customer Profiles cross-service confused deputy prevention</a>.</p>
    /// </note>
    pub fn exporting_config(&self) -> ::std::option::Option<&crate::types::ExportingConfig> {
        self.exporting_config.as_ref()
    }
}
impl RuleBasedMatchingRequest {
    /// Creates a new builder-style object to manufacture [`RuleBasedMatchingRequest`](crate::types::RuleBasedMatchingRequest).
    pub fn builder() -> crate::types::builders::RuleBasedMatchingRequestBuilder {
        crate::types::builders::RuleBasedMatchingRequestBuilder::default()
    }
}

/// A builder for [`RuleBasedMatchingRequest`](crate::types::RuleBasedMatchingRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuleBasedMatchingRequestBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) matching_rules: ::std::option::Option<::std::vec::Vec<crate::types::MatchingRule>>,
    pub(crate) max_allowed_rule_level_for_merging: ::std::option::Option<i32>,
    pub(crate) max_allowed_rule_level_for_matching: ::std::option::Option<i32>,
    pub(crate) attribute_types_selector: ::std::option::Option<crate::types::AttributeTypesSelector>,
    pub(crate) conflict_resolution: ::std::option::Option<crate::types::ConflictResolution>,
    pub(crate) exporting_config: ::std::option::Option<crate::types::ExportingConfig>,
}
impl RuleBasedMatchingRequestBuilder {
    /// <p>The flag that enables the rule-based matching process of duplicate profiles.</p>
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>The flag that enables the rule-based matching process of duplicate profiles.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>The flag that enables the rule-based matching process of duplicate profiles.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Appends an item to `matching_rules`.
    ///
    /// To override the contents of this collection use [`set_matching_rules`](Self::set_matching_rules).
    ///
    /// <p>Configures how the rule-based matching process should match profiles. You can have up to 15 <code>MatchingRule</code> in the <code>MatchingRules</code>.</p>
    pub fn matching_rules(mut self, input: crate::types::MatchingRule) -> Self {
        let mut v = self.matching_rules.unwrap_or_default();
        v.push(input);
        self.matching_rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>Configures how the rule-based matching process should match profiles. You can have up to 15 <code>MatchingRule</code> in the <code>MatchingRules</code>.</p>
    pub fn set_matching_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MatchingRule>>) -> Self {
        self.matching_rules = input;
        self
    }
    /// <p>Configures how the rule-based matching process should match profiles. You can have up to 15 <code>MatchingRule</code> in the <code>MatchingRules</code>.</p>
    pub fn get_matching_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MatchingRule>> {
        &self.matching_rules
    }
    /// <p><a href="https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_MatchingRule.html">MatchingRule</a></p>
    pub fn max_allowed_rule_level_for_merging(mut self, input: i32) -> Self {
        self.max_allowed_rule_level_for_merging = ::std::option::Option::Some(input);
        self
    }
    /// <p><a href="https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_MatchingRule.html">MatchingRule</a></p>
    pub fn set_max_allowed_rule_level_for_merging(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_allowed_rule_level_for_merging = input;
        self
    }
    /// <p><a href="https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_MatchingRule.html">MatchingRule</a></p>
    pub fn get_max_allowed_rule_level_for_merging(&self) -> &::std::option::Option<i32> {
        &self.max_allowed_rule_level_for_merging
    }
    /// <p>Indicates the maximum allowed rule level.</p>
    pub fn max_allowed_rule_level_for_matching(mut self, input: i32) -> Self {
        self.max_allowed_rule_level_for_matching = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the maximum allowed rule level.</p>
    pub fn set_max_allowed_rule_level_for_matching(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_allowed_rule_level_for_matching = input;
        self
    }
    /// <p>Indicates the maximum allowed rule level.</p>
    pub fn get_max_allowed_rule_level_for_matching(&self) -> &::std::option::Option<i32> {
        &self.max_allowed_rule_level_for_matching
    }
    /// <p>Configures information about the <code>AttributeTypesSelector</code> where the rule-based identity resolution uses to match profiles.</p>
    pub fn attribute_types_selector(mut self, input: crate::types::AttributeTypesSelector) -> Self {
        self.attribute_types_selector = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures information about the <code>AttributeTypesSelector</code> where the rule-based identity resolution uses to match profiles.</p>
    pub fn set_attribute_types_selector(mut self, input: ::std::option::Option<crate::types::AttributeTypesSelector>) -> Self {
        self.attribute_types_selector = input;
        self
    }
    /// <p>Configures information about the <code>AttributeTypesSelector</code> where the rule-based identity resolution uses to match profiles.</p>
    pub fn get_attribute_types_selector(&self) -> &::std::option::Option<crate::types::AttributeTypesSelector> {
        &self.attribute_types_selector
    }
    /// <p>How the auto-merging process should resolve conflicts between different profiles.</p>
    pub fn conflict_resolution(mut self, input: crate::types::ConflictResolution) -> Self {
        self.conflict_resolution = ::std::option::Option::Some(input);
        self
    }
    /// <p>How the auto-merging process should resolve conflicts between different profiles.</p>
    pub fn set_conflict_resolution(mut self, input: ::std::option::Option<crate::types::ConflictResolution>) -> Self {
        self.conflict_resolution = input;
        self
    }
    /// <p>How the auto-merging process should resolve conflicts between different profiles.</p>
    pub fn get_conflict_resolution(&self) -> &::std::option::Option<crate::types::ConflictResolution> {
        &self.conflict_resolution
    }
    /// <p>Configuration information about the S3 bucket where Identity Resolution Jobs writes result files.</p><note>
    /// <p>You need to give Customer Profiles service principal write permission to your S3 bucket. Otherwise, you'll get an exception in the API response. For an example policy, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/cross-service-confused-deputy-prevention.html#customer-profiles-cross-service">Amazon Connect Customer Profiles cross-service confused deputy prevention</a>.</p>
    /// </note>
    pub fn exporting_config(mut self, input: crate::types::ExportingConfig) -> Self {
        self.exporting_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration information about the S3 bucket where Identity Resolution Jobs writes result files.</p><note>
    /// <p>You need to give Customer Profiles service principal write permission to your S3 bucket. Otherwise, you'll get an exception in the API response. For an example policy, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/cross-service-confused-deputy-prevention.html#customer-profiles-cross-service">Amazon Connect Customer Profiles cross-service confused deputy prevention</a>.</p>
    /// </note>
    pub fn set_exporting_config(mut self, input: ::std::option::Option<crate::types::ExportingConfig>) -> Self {
        self.exporting_config = input;
        self
    }
    /// <p>Configuration information about the S3 bucket where Identity Resolution Jobs writes result files.</p><note>
    /// <p>You need to give Customer Profiles service principal write permission to your S3 bucket. Otherwise, you'll get an exception in the API response. For an example policy, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/cross-service-confused-deputy-prevention.html#customer-profiles-cross-service">Amazon Connect Customer Profiles cross-service confused deputy prevention</a>.</p>
    /// </note>
    pub fn get_exporting_config(&self) -> &::std::option::Option<crate::types::ExportingConfig> {
        &self.exporting_config
    }
    /// Consumes the builder and constructs a [`RuleBasedMatchingRequest`](crate::types::RuleBasedMatchingRequest).
    /// This method will fail if any of the following fields are not set:
    /// - [`enabled`](crate::types::builders::RuleBasedMatchingRequestBuilder::enabled)
    pub fn build(self) -> ::std::result::Result<crate::types::RuleBasedMatchingRequest, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RuleBasedMatchingRequest {
            enabled: self.enabled.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "enabled",
                    "enabled was not specified but it is required when building RuleBasedMatchingRequest",
                )
            })?,
            matching_rules: self.matching_rules,
            max_allowed_rule_level_for_merging: self.max_allowed_rule_level_for_merging,
            max_allowed_rule_level_for_matching: self.max_allowed_rule_level_for_matching,
            attribute_types_selector: self.attribute_types_selector,
            conflict_resolution: self.conflict_resolution,
            exporting_config: self.exporting_config,
        })
    }
}
