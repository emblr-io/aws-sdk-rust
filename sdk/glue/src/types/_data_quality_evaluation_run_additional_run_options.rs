// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Additional run options you can specify for an evaluation run.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataQualityEvaluationRunAdditionalRunOptions {
    /// <p>Whether or not to enable CloudWatch metrics.</p>
    pub cloud_watch_metrics_enabled: ::std::option::Option<bool>,
    /// <p>Prefix for Amazon S3 to store results.</p>
    pub results_s3_prefix: ::std::option::Option<::std::string::String>,
    /// <p>Set the evaluation method for composite rules in the ruleset to ROW/COLUMN</p>
    pub composite_rule_evaluation_method: ::std::option::Option<crate::types::DqCompositeRuleEvaluationMethod>,
}
impl DataQualityEvaluationRunAdditionalRunOptions {
    /// <p>Whether or not to enable CloudWatch metrics.</p>
    pub fn cloud_watch_metrics_enabled(&self) -> ::std::option::Option<bool> {
        self.cloud_watch_metrics_enabled
    }
    /// <p>Prefix for Amazon S3 to store results.</p>
    pub fn results_s3_prefix(&self) -> ::std::option::Option<&str> {
        self.results_s3_prefix.as_deref()
    }
    /// <p>Set the evaluation method for composite rules in the ruleset to ROW/COLUMN</p>
    pub fn composite_rule_evaluation_method(&self) -> ::std::option::Option<&crate::types::DqCompositeRuleEvaluationMethod> {
        self.composite_rule_evaluation_method.as_ref()
    }
}
impl DataQualityEvaluationRunAdditionalRunOptions {
    /// Creates a new builder-style object to manufacture [`DataQualityEvaluationRunAdditionalRunOptions`](crate::types::DataQualityEvaluationRunAdditionalRunOptions).
    pub fn builder() -> crate::types::builders::DataQualityEvaluationRunAdditionalRunOptionsBuilder {
        crate::types::builders::DataQualityEvaluationRunAdditionalRunOptionsBuilder::default()
    }
}

/// A builder for [`DataQualityEvaluationRunAdditionalRunOptions`](crate::types::DataQualityEvaluationRunAdditionalRunOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataQualityEvaluationRunAdditionalRunOptionsBuilder {
    pub(crate) cloud_watch_metrics_enabled: ::std::option::Option<bool>,
    pub(crate) results_s3_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) composite_rule_evaluation_method: ::std::option::Option<crate::types::DqCompositeRuleEvaluationMethod>,
}
impl DataQualityEvaluationRunAdditionalRunOptionsBuilder {
    /// <p>Whether or not to enable CloudWatch metrics.</p>
    pub fn cloud_watch_metrics_enabled(mut self, input: bool) -> Self {
        self.cloud_watch_metrics_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether or not to enable CloudWatch metrics.</p>
    pub fn set_cloud_watch_metrics_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.cloud_watch_metrics_enabled = input;
        self
    }
    /// <p>Whether or not to enable CloudWatch metrics.</p>
    pub fn get_cloud_watch_metrics_enabled(&self) -> &::std::option::Option<bool> {
        &self.cloud_watch_metrics_enabled
    }
    /// <p>Prefix for Amazon S3 to store results.</p>
    pub fn results_s3_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.results_s3_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Prefix for Amazon S3 to store results.</p>
    pub fn set_results_s3_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.results_s3_prefix = input;
        self
    }
    /// <p>Prefix for Amazon S3 to store results.</p>
    pub fn get_results_s3_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.results_s3_prefix
    }
    /// <p>Set the evaluation method for composite rules in the ruleset to ROW/COLUMN</p>
    pub fn composite_rule_evaluation_method(mut self, input: crate::types::DqCompositeRuleEvaluationMethod) -> Self {
        self.composite_rule_evaluation_method = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set the evaluation method for composite rules in the ruleset to ROW/COLUMN</p>
    pub fn set_composite_rule_evaluation_method(mut self, input: ::std::option::Option<crate::types::DqCompositeRuleEvaluationMethod>) -> Self {
        self.composite_rule_evaluation_method = input;
        self
    }
    /// <p>Set the evaluation method for composite rules in the ruleset to ROW/COLUMN</p>
    pub fn get_composite_rule_evaluation_method(&self) -> &::std::option::Option<crate::types::DqCompositeRuleEvaluationMethod> {
        &self.composite_rule_evaluation_method
    }
    /// Consumes the builder and constructs a [`DataQualityEvaluationRunAdditionalRunOptions`](crate::types::DataQualityEvaluationRunAdditionalRunOptions).
    pub fn build(self) -> crate::types::DataQualityEvaluationRunAdditionalRunOptions {
        crate::types::DataQualityEvaluationRunAdditionalRunOptions {
            cloud_watch_metrics_enabled: self.cloud_watch_metrics_enabled,
            results_s3_prefix: self.results_s3_prefix,
            composite_rule_evaluation_method: self.composite_rule_evaluation_method,
        }
    }
}
