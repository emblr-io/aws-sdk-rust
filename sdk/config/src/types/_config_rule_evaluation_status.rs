// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Status information for your Config Managed rules and Config Custom Policy rules. The status includes information such as the last time the rule ran, the last time it failed, and the related error for the last failure.</p>
/// <p>This operation does not return status information about Config Custom Lambda rules.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConfigRuleEvaluationStatus {
    /// <p>The name of the Config rule.</p>
    pub config_rule_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the Config rule.</p>
    pub config_rule_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Config rule.</p>
    pub config_rule_id: ::std::option::Option<::std::string::String>,
    /// <p>The time that Config last successfully invoked the Config rule to evaluate your Amazon Web Services resources.</p>
    pub last_successful_invocation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that Config last failed to invoke the Config rule to evaluate your Amazon Web Services resources.</p>
    pub last_failed_invocation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that Config last successfully evaluated your Amazon Web Services resources against the rule.</p>
    pub last_successful_evaluation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that Config last failed to evaluate your Amazon Web Services resources against the rule.</p>
    pub last_failed_evaluation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that you first activated the Config rule.</p>
    pub first_activated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that you last turned off the Config rule.</p>
    pub last_deactivated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The error code that Config returned when the rule last failed.</p>
    pub last_error_code: ::std::option::Option<::std::string::String>,
    /// <p>The error message that Config returned when the rule last failed.</p>
    pub last_error_message: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether Config has evaluated your resources against the rule at least once.</p>
    /// <ul>
    /// <li>
    /// <p><code>true</code> - Config has evaluated your Amazon Web Services resources against the rule at least once.</p></li>
    /// <li>
    /// <p><code>false</code> - Config has not finished evaluating your Amazon Web Services resources against the rule at least once.</p></li>
    /// </ul>
    pub first_evaluation_started: bool,
    /// <p>The status of the last attempted delivery of a debug log for your Config Custom Policy rules. Either <code>Successful</code> or <code>Failed</code>.</p>
    pub last_debug_log_delivery_status: ::std::option::Option<::std::string::String>,
    /// <p>The reason Config was not able to deliver a debug log. This is for the last failed attempt to retrieve a debug log for your Config Custom Policy rules.</p>
    pub last_debug_log_delivery_status_reason: ::std::option::Option<::std::string::String>,
    /// <p>The time Config last attempted to deliver a debug log for your Config Custom Policy rules.</p>
    pub last_debug_log_delivery_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ConfigRuleEvaluationStatus {
    /// <p>The name of the Config rule.</p>
    pub fn config_rule_name(&self) -> ::std::option::Option<&str> {
        self.config_rule_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Config rule.</p>
    pub fn config_rule_arn(&self) -> ::std::option::Option<&str> {
        self.config_rule_arn.as_deref()
    }
    /// <p>The ID of the Config rule.</p>
    pub fn config_rule_id(&self) -> ::std::option::Option<&str> {
        self.config_rule_id.as_deref()
    }
    /// <p>The time that Config last successfully invoked the Config rule to evaluate your Amazon Web Services resources.</p>
    pub fn last_successful_invocation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_successful_invocation_time.as_ref()
    }
    /// <p>The time that Config last failed to invoke the Config rule to evaluate your Amazon Web Services resources.</p>
    pub fn last_failed_invocation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_failed_invocation_time.as_ref()
    }
    /// <p>The time that Config last successfully evaluated your Amazon Web Services resources against the rule.</p>
    pub fn last_successful_evaluation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_successful_evaluation_time.as_ref()
    }
    /// <p>The time that Config last failed to evaluate your Amazon Web Services resources against the rule.</p>
    pub fn last_failed_evaluation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_failed_evaluation_time.as_ref()
    }
    /// <p>The time that you first activated the Config rule.</p>
    pub fn first_activated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.first_activated_time.as_ref()
    }
    /// <p>The time that you last turned off the Config rule.</p>
    pub fn last_deactivated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_deactivated_time.as_ref()
    }
    /// <p>The error code that Config returned when the rule last failed.</p>
    pub fn last_error_code(&self) -> ::std::option::Option<&str> {
        self.last_error_code.as_deref()
    }
    /// <p>The error message that Config returned when the rule last failed.</p>
    pub fn last_error_message(&self) -> ::std::option::Option<&str> {
        self.last_error_message.as_deref()
    }
    /// <p>Indicates whether Config has evaluated your resources against the rule at least once.</p>
    /// <ul>
    /// <li>
    /// <p><code>true</code> - Config has evaluated your Amazon Web Services resources against the rule at least once.</p></li>
    /// <li>
    /// <p><code>false</code> - Config has not finished evaluating your Amazon Web Services resources against the rule at least once.</p></li>
    /// </ul>
    pub fn first_evaluation_started(&self) -> bool {
        self.first_evaluation_started
    }
    /// <p>The status of the last attempted delivery of a debug log for your Config Custom Policy rules. Either <code>Successful</code> or <code>Failed</code>.</p>
    pub fn last_debug_log_delivery_status(&self) -> ::std::option::Option<&str> {
        self.last_debug_log_delivery_status.as_deref()
    }
    /// <p>The reason Config was not able to deliver a debug log. This is for the last failed attempt to retrieve a debug log for your Config Custom Policy rules.</p>
    pub fn last_debug_log_delivery_status_reason(&self) -> ::std::option::Option<&str> {
        self.last_debug_log_delivery_status_reason.as_deref()
    }
    /// <p>The time Config last attempted to deliver a debug log for your Config Custom Policy rules.</p>
    pub fn last_debug_log_delivery_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_debug_log_delivery_time.as_ref()
    }
}
impl ConfigRuleEvaluationStatus {
    /// Creates a new builder-style object to manufacture [`ConfigRuleEvaluationStatus`](crate::types::ConfigRuleEvaluationStatus).
    pub fn builder() -> crate::types::builders::ConfigRuleEvaluationStatusBuilder {
        crate::types::builders::ConfigRuleEvaluationStatusBuilder::default()
    }
}

/// A builder for [`ConfigRuleEvaluationStatus`](crate::types::ConfigRuleEvaluationStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfigRuleEvaluationStatusBuilder {
    pub(crate) config_rule_name: ::std::option::Option<::std::string::String>,
    pub(crate) config_rule_arn: ::std::option::Option<::std::string::String>,
    pub(crate) config_rule_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_successful_invocation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_failed_invocation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_successful_evaluation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_failed_evaluation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) first_activated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_deactivated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_error_code: ::std::option::Option<::std::string::String>,
    pub(crate) last_error_message: ::std::option::Option<::std::string::String>,
    pub(crate) first_evaluation_started: ::std::option::Option<bool>,
    pub(crate) last_debug_log_delivery_status: ::std::option::Option<::std::string::String>,
    pub(crate) last_debug_log_delivery_status_reason: ::std::option::Option<::std::string::String>,
    pub(crate) last_debug_log_delivery_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ConfigRuleEvaluationStatusBuilder {
    /// <p>The name of the Config rule.</p>
    pub fn config_rule_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.config_rule_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Config rule.</p>
    pub fn set_config_rule_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.config_rule_name = input;
        self
    }
    /// <p>The name of the Config rule.</p>
    pub fn get_config_rule_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.config_rule_name
    }
    /// <p>The Amazon Resource Name (ARN) of the Config rule.</p>
    pub fn config_rule_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.config_rule_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Config rule.</p>
    pub fn set_config_rule_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.config_rule_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Config rule.</p>
    pub fn get_config_rule_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.config_rule_arn
    }
    /// <p>The ID of the Config rule.</p>
    pub fn config_rule_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.config_rule_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Config rule.</p>
    pub fn set_config_rule_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.config_rule_id = input;
        self
    }
    /// <p>The ID of the Config rule.</p>
    pub fn get_config_rule_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.config_rule_id
    }
    /// <p>The time that Config last successfully invoked the Config rule to evaluate your Amazon Web Services resources.</p>
    pub fn last_successful_invocation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_successful_invocation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that Config last successfully invoked the Config rule to evaluate your Amazon Web Services resources.</p>
    pub fn set_last_successful_invocation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_successful_invocation_time = input;
        self
    }
    /// <p>The time that Config last successfully invoked the Config rule to evaluate your Amazon Web Services resources.</p>
    pub fn get_last_successful_invocation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_successful_invocation_time
    }
    /// <p>The time that Config last failed to invoke the Config rule to evaluate your Amazon Web Services resources.</p>
    pub fn last_failed_invocation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_failed_invocation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that Config last failed to invoke the Config rule to evaluate your Amazon Web Services resources.</p>
    pub fn set_last_failed_invocation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_failed_invocation_time = input;
        self
    }
    /// <p>The time that Config last failed to invoke the Config rule to evaluate your Amazon Web Services resources.</p>
    pub fn get_last_failed_invocation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_failed_invocation_time
    }
    /// <p>The time that Config last successfully evaluated your Amazon Web Services resources against the rule.</p>
    pub fn last_successful_evaluation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_successful_evaluation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that Config last successfully evaluated your Amazon Web Services resources against the rule.</p>
    pub fn set_last_successful_evaluation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_successful_evaluation_time = input;
        self
    }
    /// <p>The time that Config last successfully evaluated your Amazon Web Services resources against the rule.</p>
    pub fn get_last_successful_evaluation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_successful_evaluation_time
    }
    /// <p>The time that Config last failed to evaluate your Amazon Web Services resources against the rule.</p>
    pub fn last_failed_evaluation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_failed_evaluation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that Config last failed to evaluate your Amazon Web Services resources against the rule.</p>
    pub fn set_last_failed_evaluation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_failed_evaluation_time = input;
        self
    }
    /// <p>The time that Config last failed to evaluate your Amazon Web Services resources against the rule.</p>
    pub fn get_last_failed_evaluation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_failed_evaluation_time
    }
    /// <p>The time that you first activated the Config rule.</p>
    pub fn first_activated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.first_activated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that you first activated the Config rule.</p>
    pub fn set_first_activated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.first_activated_time = input;
        self
    }
    /// <p>The time that you first activated the Config rule.</p>
    pub fn get_first_activated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.first_activated_time
    }
    /// <p>The time that you last turned off the Config rule.</p>
    pub fn last_deactivated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_deactivated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that you last turned off the Config rule.</p>
    pub fn set_last_deactivated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_deactivated_time = input;
        self
    }
    /// <p>The time that you last turned off the Config rule.</p>
    pub fn get_last_deactivated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_deactivated_time
    }
    /// <p>The error code that Config returned when the rule last failed.</p>
    pub fn last_error_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_error_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error code that Config returned when the rule last failed.</p>
    pub fn set_last_error_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_error_code = input;
        self
    }
    /// <p>The error code that Config returned when the rule last failed.</p>
    pub fn get_last_error_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_error_code
    }
    /// <p>The error message that Config returned when the rule last failed.</p>
    pub fn last_error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message that Config returned when the rule last failed.</p>
    pub fn set_last_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_error_message = input;
        self
    }
    /// <p>The error message that Config returned when the rule last failed.</p>
    pub fn get_last_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_error_message
    }
    /// <p>Indicates whether Config has evaluated your resources against the rule at least once.</p>
    /// <ul>
    /// <li>
    /// <p><code>true</code> - Config has evaluated your Amazon Web Services resources against the rule at least once.</p></li>
    /// <li>
    /// <p><code>false</code> - Config has not finished evaluating your Amazon Web Services resources against the rule at least once.</p></li>
    /// </ul>
    pub fn first_evaluation_started(mut self, input: bool) -> Self {
        self.first_evaluation_started = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether Config has evaluated your resources against the rule at least once.</p>
    /// <ul>
    /// <li>
    /// <p><code>true</code> - Config has evaluated your Amazon Web Services resources against the rule at least once.</p></li>
    /// <li>
    /// <p><code>false</code> - Config has not finished evaluating your Amazon Web Services resources against the rule at least once.</p></li>
    /// </ul>
    pub fn set_first_evaluation_started(mut self, input: ::std::option::Option<bool>) -> Self {
        self.first_evaluation_started = input;
        self
    }
    /// <p>Indicates whether Config has evaluated your resources against the rule at least once.</p>
    /// <ul>
    /// <li>
    /// <p><code>true</code> - Config has evaluated your Amazon Web Services resources against the rule at least once.</p></li>
    /// <li>
    /// <p><code>false</code> - Config has not finished evaluating your Amazon Web Services resources against the rule at least once.</p></li>
    /// </ul>
    pub fn get_first_evaluation_started(&self) -> &::std::option::Option<bool> {
        &self.first_evaluation_started
    }
    /// <p>The status of the last attempted delivery of a debug log for your Config Custom Policy rules. Either <code>Successful</code> or <code>Failed</code>.</p>
    pub fn last_debug_log_delivery_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_debug_log_delivery_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the last attempted delivery of a debug log for your Config Custom Policy rules. Either <code>Successful</code> or <code>Failed</code>.</p>
    pub fn set_last_debug_log_delivery_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_debug_log_delivery_status = input;
        self
    }
    /// <p>The status of the last attempted delivery of a debug log for your Config Custom Policy rules. Either <code>Successful</code> or <code>Failed</code>.</p>
    pub fn get_last_debug_log_delivery_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_debug_log_delivery_status
    }
    /// <p>The reason Config was not able to deliver a debug log. This is for the last failed attempt to retrieve a debug log for your Config Custom Policy rules.</p>
    pub fn last_debug_log_delivery_status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_debug_log_delivery_status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason Config was not able to deliver a debug log. This is for the last failed attempt to retrieve a debug log for your Config Custom Policy rules.</p>
    pub fn set_last_debug_log_delivery_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_debug_log_delivery_status_reason = input;
        self
    }
    /// <p>The reason Config was not able to deliver a debug log. This is for the last failed attempt to retrieve a debug log for your Config Custom Policy rules.</p>
    pub fn get_last_debug_log_delivery_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_debug_log_delivery_status_reason
    }
    /// <p>The time Config last attempted to deliver a debug log for your Config Custom Policy rules.</p>
    pub fn last_debug_log_delivery_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_debug_log_delivery_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time Config last attempted to deliver a debug log for your Config Custom Policy rules.</p>
    pub fn set_last_debug_log_delivery_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_debug_log_delivery_time = input;
        self
    }
    /// <p>The time Config last attempted to deliver a debug log for your Config Custom Policy rules.</p>
    pub fn get_last_debug_log_delivery_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_debug_log_delivery_time
    }
    /// Consumes the builder and constructs a [`ConfigRuleEvaluationStatus`](crate::types::ConfigRuleEvaluationStatus).
    pub fn build(self) -> crate::types::ConfigRuleEvaluationStatus {
        crate::types::ConfigRuleEvaluationStatus {
            config_rule_name: self.config_rule_name,
            config_rule_arn: self.config_rule_arn,
            config_rule_id: self.config_rule_id,
            last_successful_invocation_time: self.last_successful_invocation_time,
            last_failed_invocation_time: self.last_failed_invocation_time,
            last_successful_evaluation_time: self.last_successful_evaluation_time,
            last_failed_evaluation_time: self.last_failed_evaluation_time,
            first_activated_time: self.first_activated_time,
            last_deactivated_time: self.last_deactivated_time,
            last_error_code: self.last_error_code,
            last_error_message: self.last_error_message,
            first_evaluation_started: self.first_evaluation_started.unwrap_or_default(),
            last_debug_log_delivery_status: self.last_debug_log_delivery_status,
            last_debug_log_delivery_status_reason: self.last_debug_log_delivery_status_reason,
            last_debug_log_delivery_time: self.last_debug_log_delivery_time,
        }
    }
}
