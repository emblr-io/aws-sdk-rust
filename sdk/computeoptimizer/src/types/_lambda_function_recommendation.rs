// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an Lambda function recommendation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LambdaFunctionRecommendation {
    /// <p>The Amazon Resource Name (ARN) of the current function.</p>
    pub function_arn: ::std::option::Option<::std::string::String>,
    /// <p>The version number of the current function.</p>
    pub function_version: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID of the function.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The amount of memory, in MB, that's allocated to the current function.</p>
    pub current_memory_size: i32,
    /// <p>The number of times your function code was applied during the look-back period.</p>
    pub number_of_invocations: i64,
    /// <p>An array of objects that describe the utilization metrics of the function.</p>
    pub utilization_metrics: ::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionUtilizationMetric>>,
    /// <p>The number of days for which utilization metrics were analyzed for the function.</p>
    pub lookback_period_in_days: f64,
    /// <p>The timestamp of when the function recommendation was last generated.</p>
    pub last_refresh_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The finding classification of the function.</p>
    /// <p>Findings for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>Optimized</code> </b> — The function is correctly provisioned to run your workload based on its current configuration and its utilization history. This finding classification does not include finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>NotOptimized</code> </b> — The function is performing at a higher level (over-provisioned) or at a lower level (under-provisioned) than required for your workload because its current configuration is not optimal. Over-provisioned resources might lead to unnecessary infrastructure cost, and under-provisioned resources might lead to poor application performance. This finding classification can include the <code>MemoryUnderprovisioned</code> and <code>MemoryUnderprovisioned</code> finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>Unavailable</code> </b> — Compute Optimizer was unable to generate a recommendation for the function. This could be because the function has not accumulated sufficient metric data, or the function does not qualify for a recommendation. This finding classification can include the <code>InsufficientData</code> and <code>Inconclusive</code> finding reason codes.</p><note>
    /// <p>Functions with a finding of unavailable are not returned unless you specify the <code>filter</code> parameter with a value of <code>Unavailable</code> in your <code>GetLambdaFunctionRecommendations</code> request.</p>
    /// </note></li>
    /// </ul>
    pub finding: ::std::option::Option<crate::types::LambdaFunctionRecommendationFinding>,
    /// <p>The reason for the finding classification of the function.</p><note>
    /// <p>Functions that have a finding classification of <code>Optimized</code> don't have a finding reason code.</p>
    /// </note>
    /// <p>Finding reason codes for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>MemoryOverprovisioned</code> </b> — The function is over-provisioned when its memory configuration can be sized down while still meeting the performance requirements of your workload. An over-provisioned function might lead to unnecessary infrastructure cost. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>MemoryUnderprovisioned</code> </b> — The function is under-provisioned when its memory configuration doesn't meet the performance requirements of the workload. An under-provisioned function might lead to poor application performance. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>InsufficientData</code> </b> — The function does not have sufficient metric data for Compute Optimizer to generate a recommendation. For more information, see the <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/requirements.html">Supported resources and requirements</a> in the <i>Compute Optimizer User Guide</i>. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>Inconclusive</code> </b> — The function does not qualify for a recommendation because Compute Optimizer cannot generate a recommendation with a high degree of confidence. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// </ul>
    pub finding_reason_codes: ::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionRecommendationFindingReasonCode>>,
    /// <p>An array of objects that describe the memory configuration recommendation options for the function.</p>
    pub memory_size_recommendation_options: ::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionMemoryRecommendationOption>>,
    /// <p>The risk of the current Lambda function not meeting the performance needs of its workloads. The higher the risk, the more likely the current Lambda function requires more memory.</p>
    pub current_performance_risk: ::std::option::Option<crate::types::CurrentPerformanceRisk>,
    /// <p>Describes the effective recommendation preferences for Lambda functions.</p>
    pub effective_recommendation_preferences: ::std::option::Option<crate::types::LambdaEffectiveRecommendationPreferences>,
    /// <p>A list of tags assigned to your Lambda function recommendations.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl LambdaFunctionRecommendation {
    /// <p>The Amazon Resource Name (ARN) of the current function.</p>
    pub fn function_arn(&self) -> ::std::option::Option<&str> {
        self.function_arn.as_deref()
    }
    /// <p>The version number of the current function.</p>
    pub fn function_version(&self) -> ::std::option::Option<&str> {
        self.function_version.as_deref()
    }
    /// <p>The Amazon Web Services account ID of the function.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The amount of memory, in MB, that's allocated to the current function.</p>
    pub fn current_memory_size(&self) -> i32 {
        self.current_memory_size
    }
    /// <p>The number of times your function code was applied during the look-back period.</p>
    pub fn number_of_invocations(&self) -> i64 {
        self.number_of_invocations
    }
    /// <p>An array of objects that describe the utilization metrics of the function.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.utilization_metrics.is_none()`.
    pub fn utilization_metrics(&self) -> &[crate::types::LambdaFunctionUtilizationMetric] {
        self.utilization_metrics.as_deref().unwrap_or_default()
    }
    /// <p>The number of days for which utilization metrics were analyzed for the function.</p>
    pub fn lookback_period_in_days(&self) -> f64 {
        self.lookback_period_in_days
    }
    /// <p>The timestamp of when the function recommendation was last generated.</p>
    pub fn last_refresh_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_refresh_timestamp.as_ref()
    }
    /// <p>The finding classification of the function.</p>
    /// <p>Findings for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>Optimized</code> </b> — The function is correctly provisioned to run your workload based on its current configuration and its utilization history. This finding classification does not include finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>NotOptimized</code> </b> — The function is performing at a higher level (over-provisioned) or at a lower level (under-provisioned) than required for your workload because its current configuration is not optimal. Over-provisioned resources might lead to unnecessary infrastructure cost, and under-provisioned resources might lead to poor application performance. This finding classification can include the <code>MemoryUnderprovisioned</code> and <code>MemoryUnderprovisioned</code> finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>Unavailable</code> </b> — Compute Optimizer was unable to generate a recommendation for the function. This could be because the function has not accumulated sufficient metric data, or the function does not qualify for a recommendation. This finding classification can include the <code>InsufficientData</code> and <code>Inconclusive</code> finding reason codes.</p><note>
    /// <p>Functions with a finding of unavailable are not returned unless you specify the <code>filter</code> parameter with a value of <code>Unavailable</code> in your <code>GetLambdaFunctionRecommendations</code> request.</p>
    /// </note></li>
    /// </ul>
    pub fn finding(&self) -> ::std::option::Option<&crate::types::LambdaFunctionRecommendationFinding> {
        self.finding.as_ref()
    }
    /// <p>The reason for the finding classification of the function.</p><note>
    /// <p>Functions that have a finding classification of <code>Optimized</code> don't have a finding reason code.</p>
    /// </note>
    /// <p>Finding reason codes for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>MemoryOverprovisioned</code> </b> — The function is over-provisioned when its memory configuration can be sized down while still meeting the performance requirements of your workload. An over-provisioned function might lead to unnecessary infrastructure cost. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>MemoryUnderprovisioned</code> </b> — The function is under-provisioned when its memory configuration doesn't meet the performance requirements of the workload. An under-provisioned function might lead to poor application performance. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>InsufficientData</code> </b> — The function does not have sufficient metric data for Compute Optimizer to generate a recommendation. For more information, see the <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/requirements.html">Supported resources and requirements</a> in the <i>Compute Optimizer User Guide</i>. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>Inconclusive</code> </b> — The function does not qualify for a recommendation because Compute Optimizer cannot generate a recommendation with a high degree of confidence. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.finding_reason_codes.is_none()`.
    pub fn finding_reason_codes(&self) -> &[crate::types::LambdaFunctionRecommendationFindingReasonCode] {
        self.finding_reason_codes.as_deref().unwrap_or_default()
    }
    /// <p>An array of objects that describe the memory configuration recommendation options for the function.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.memory_size_recommendation_options.is_none()`.
    pub fn memory_size_recommendation_options(&self) -> &[crate::types::LambdaFunctionMemoryRecommendationOption] {
        self.memory_size_recommendation_options.as_deref().unwrap_or_default()
    }
    /// <p>The risk of the current Lambda function not meeting the performance needs of its workloads. The higher the risk, the more likely the current Lambda function requires more memory.</p>
    pub fn current_performance_risk(&self) -> ::std::option::Option<&crate::types::CurrentPerformanceRisk> {
        self.current_performance_risk.as_ref()
    }
    /// <p>Describes the effective recommendation preferences for Lambda functions.</p>
    pub fn effective_recommendation_preferences(&self) -> ::std::option::Option<&crate::types::LambdaEffectiveRecommendationPreferences> {
        self.effective_recommendation_preferences.as_ref()
    }
    /// <p>A list of tags assigned to your Lambda function recommendations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl LambdaFunctionRecommendation {
    /// Creates a new builder-style object to manufacture [`LambdaFunctionRecommendation`](crate::types::LambdaFunctionRecommendation).
    pub fn builder() -> crate::types::builders::LambdaFunctionRecommendationBuilder {
        crate::types::builders::LambdaFunctionRecommendationBuilder::default()
    }
}

/// A builder for [`LambdaFunctionRecommendation`](crate::types::LambdaFunctionRecommendation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LambdaFunctionRecommendationBuilder {
    pub(crate) function_arn: ::std::option::Option<::std::string::String>,
    pub(crate) function_version: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) current_memory_size: ::std::option::Option<i32>,
    pub(crate) number_of_invocations: ::std::option::Option<i64>,
    pub(crate) utilization_metrics: ::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionUtilizationMetric>>,
    pub(crate) lookback_period_in_days: ::std::option::Option<f64>,
    pub(crate) last_refresh_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) finding: ::std::option::Option<crate::types::LambdaFunctionRecommendationFinding>,
    pub(crate) finding_reason_codes: ::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionRecommendationFindingReasonCode>>,
    pub(crate) memory_size_recommendation_options: ::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionMemoryRecommendationOption>>,
    pub(crate) current_performance_risk: ::std::option::Option<crate::types::CurrentPerformanceRisk>,
    pub(crate) effective_recommendation_preferences: ::std::option::Option<crate::types::LambdaEffectiveRecommendationPreferences>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl LambdaFunctionRecommendationBuilder {
    /// <p>The Amazon Resource Name (ARN) of the current function.</p>
    pub fn function_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.function_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the current function.</p>
    pub fn set_function_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.function_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the current function.</p>
    pub fn get_function_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.function_arn
    }
    /// <p>The version number of the current function.</p>
    pub fn function_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.function_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version number of the current function.</p>
    pub fn set_function_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.function_version = input;
        self
    }
    /// <p>The version number of the current function.</p>
    pub fn get_function_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.function_version
    }
    /// <p>The Amazon Web Services account ID of the function.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the function.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the function.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The amount of memory, in MB, that's allocated to the current function.</p>
    pub fn current_memory_size(mut self, input: i32) -> Self {
        self.current_memory_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of memory, in MB, that's allocated to the current function.</p>
    pub fn set_current_memory_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.current_memory_size = input;
        self
    }
    /// <p>The amount of memory, in MB, that's allocated to the current function.</p>
    pub fn get_current_memory_size(&self) -> &::std::option::Option<i32> {
        &self.current_memory_size
    }
    /// <p>The number of times your function code was applied during the look-back period.</p>
    pub fn number_of_invocations(mut self, input: i64) -> Self {
        self.number_of_invocations = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of times your function code was applied during the look-back period.</p>
    pub fn set_number_of_invocations(mut self, input: ::std::option::Option<i64>) -> Self {
        self.number_of_invocations = input;
        self
    }
    /// <p>The number of times your function code was applied during the look-back period.</p>
    pub fn get_number_of_invocations(&self) -> &::std::option::Option<i64> {
        &self.number_of_invocations
    }
    /// Appends an item to `utilization_metrics`.
    ///
    /// To override the contents of this collection use [`set_utilization_metrics`](Self::set_utilization_metrics).
    ///
    /// <p>An array of objects that describe the utilization metrics of the function.</p>
    pub fn utilization_metrics(mut self, input: crate::types::LambdaFunctionUtilizationMetric) -> Self {
        let mut v = self.utilization_metrics.unwrap_or_default();
        v.push(input);
        self.utilization_metrics = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that describe the utilization metrics of the function.</p>
    pub fn set_utilization_metrics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionUtilizationMetric>>) -> Self {
        self.utilization_metrics = input;
        self
    }
    /// <p>An array of objects that describe the utilization metrics of the function.</p>
    pub fn get_utilization_metrics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionUtilizationMetric>> {
        &self.utilization_metrics
    }
    /// <p>The number of days for which utilization metrics were analyzed for the function.</p>
    pub fn lookback_period_in_days(mut self, input: f64) -> Self {
        self.lookback_period_in_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of days for which utilization metrics were analyzed for the function.</p>
    pub fn set_lookback_period_in_days(mut self, input: ::std::option::Option<f64>) -> Self {
        self.lookback_period_in_days = input;
        self
    }
    /// <p>The number of days for which utilization metrics were analyzed for the function.</p>
    pub fn get_lookback_period_in_days(&self) -> &::std::option::Option<f64> {
        &self.lookback_period_in_days
    }
    /// <p>The timestamp of when the function recommendation was last generated.</p>
    pub fn last_refresh_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_refresh_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the function recommendation was last generated.</p>
    pub fn set_last_refresh_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_refresh_timestamp = input;
        self
    }
    /// <p>The timestamp of when the function recommendation was last generated.</p>
    pub fn get_last_refresh_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_refresh_timestamp
    }
    /// <p>The finding classification of the function.</p>
    /// <p>Findings for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>Optimized</code> </b> — The function is correctly provisioned to run your workload based on its current configuration and its utilization history. This finding classification does not include finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>NotOptimized</code> </b> — The function is performing at a higher level (over-provisioned) or at a lower level (under-provisioned) than required for your workload because its current configuration is not optimal. Over-provisioned resources might lead to unnecessary infrastructure cost, and under-provisioned resources might lead to poor application performance. This finding classification can include the <code>MemoryUnderprovisioned</code> and <code>MemoryUnderprovisioned</code> finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>Unavailable</code> </b> — Compute Optimizer was unable to generate a recommendation for the function. This could be because the function has not accumulated sufficient metric data, or the function does not qualify for a recommendation. This finding classification can include the <code>InsufficientData</code> and <code>Inconclusive</code> finding reason codes.</p><note>
    /// <p>Functions with a finding of unavailable are not returned unless you specify the <code>filter</code> parameter with a value of <code>Unavailable</code> in your <code>GetLambdaFunctionRecommendations</code> request.</p>
    /// </note></li>
    /// </ul>
    pub fn finding(mut self, input: crate::types::LambdaFunctionRecommendationFinding) -> Self {
        self.finding = ::std::option::Option::Some(input);
        self
    }
    /// <p>The finding classification of the function.</p>
    /// <p>Findings for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>Optimized</code> </b> — The function is correctly provisioned to run your workload based on its current configuration and its utilization history. This finding classification does not include finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>NotOptimized</code> </b> — The function is performing at a higher level (over-provisioned) or at a lower level (under-provisioned) than required for your workload because its current configuration is not optimal. Over-provisioned resources might lead to unnecessary infrastructure cost, and under-provisioned resources might lead to poor application performance. This finding classification can include the <code>MemoryUnderprovisioned</code> and <code>MemoryUnderprovisioned</code> finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>Unavailable</code> </b> — Compute Optimizer was unable to generate a recommendation for the function. This could be because the function has not accumulated sufficient metric data, or the function does not qualify for a recommendation. This finding classification can include the <code>InsufficientData</code> and <code>Inconclusive</code> finding reason codes.</p><note>
    /// <p>Functions with a finding of unavailable are not returned unless you specify the <code>filter</code> parameter with a value of <code>Unavailable</code> in your <code>GetLambdaFunctionRecommendations</code> request.</p>
    /// </note></li>
    /// </ul>
    pub fn set_finding(mut self, input: ::std::option::Option<crate::types::LambdaFunctionRecommendationFinding>) -> Self {
        self.finding = input;
        self
    }
    /// <p>The finding classification of the function.</p>
    /// <p>Findings for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>Optimized</code> </b> — The function is correctly provisioned to run your workload based on its current configuration and its utilization history. This finding classification does not include finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>NotOptimized</code> </b> — The function is performing at a higher level (over-provisioned) or at a lower level (under-provisioned) than required for your workload because its current configuration is not optimal. Over-provisioned resources might lead to unnecessary infrastructure cost, and under-provisioned resources might lead to poor application performance. This finding classification can include the <code>MemoryUnderprovisioned</code> and <code>MemoryUnderprovisioned</code> finding reason codes.</p></li>
    /// <li>
    /// <p><b> <code>Unavailable</code> </b> — Compute Optimizer was unable to generate a recommendation for the function. This could be because the function has not accumulated sufficient metric data, or the function does not qualify for a recommendation. This finding classification can include the <code>InsufficientData</code> and <code>Inconclusive</code> finding reason codes.</p><note>
    /// <p>Functions with a finding of unavailable are not returned unless you specify the <code>filter</code> parameter with a value of <code>Unavailable</code> in your <code>GetLambdaFunctionRecommendations</code> request.</p>
    /// </note></li>
    /// </ul>
    pub fn get_finding(&self) -> &::std::option::Option<crate::types::LambdaFunctionRecommendationFinding> {
        &self.finding
    }
    /// Appends an item to `finding_reason_codes`.
    ///
    /// To override the contents of this collection use [`set_finding_reason_codes`](Self::set_finding_reason_codes).
    ///
    /// <p>The reason for the finding classification of the function.</p><note>
    /// <p>Functions that have a finding classification of <code>Optimized</code> don't have a finding reason code.</p>
    /// </note>
    /// <p>Finding reason codes for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>MemoryOverprovisioned</code> </b> — The function is over-provisioned when its memory configuration can be sized down while still meeting the performance requirements of your workload. An over-provisioned function might lead to unnecessary infrastructure cost. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>MemoryUnderprovisioned</code> </b> — The function is under-provisioned when its memory configuration doesn't meet the performance requirements of the workload. An under-provisioned function might lead to poor application performance. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>InsufficientData</code> </b> — The function does not have sufficient metric data for Compute Optimizer to generate a recommendation. For more information, see the <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/requirements.html">Supported resources and requirements</a> in the <i>Compute Optimizer User Guide</i>. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>Inconclusive</code> </b> — The function does not qualify for a recommendation because Compute Optimizer cannot generate a recommendation with a high degree of confidence. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// </ul>
    pub fn finding_reason_codes(mut self, input: crate::types::LambdaFunctionRecommendationFindingReasonCode) -> Self {
        let mut v = self.finding_reason_codes.unwrap_or_default();
        v.push(input);
        self.finding_reason_codes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The reason for the finding classification of the function.</p><note>
    /// <p>Functions that have a finding classification of <code>Optimized</code> don't have a finding reason code.</p>
    /// </note>
    /// <p>Finding reason codes for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>MemoryOverprovisioned</code> </b> — The function is over-provisioned when its memory configuration can be sized down while still meeting the performance requirements of your workload. An over-provisioned function might lead to unnecessary infrastructure cost. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>MemoryUnderprovisioned</code> </b> — The function is under-provisioned when its memory configuration doesn't meet the performance requirements of the workload. An under-provisioned function might lead to poor application performance. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>InsufficientData</code> </b> — The function does not have sufficient metric data for Compute Optimizer to generate a recommendation. For more information, see the <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/requirements.html">Supported resources and requirements</a> in the <i>Compute Optimizer User Guide</i>. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>Inconclusive</code> </b> — The function does not qualify for a recommendation because Compute Optimizer cannot generate a recommendation with a high degree of confidence. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// </ul>
    pub fn set_finding_reason_codes(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionRecommendationFindingReasonCode>>,
    ) -> Self {
        self.finding_reason_codes = input;
        self
    }
    /// <p>The reason for the finding classification of the function.</p><note>
    /// <p>Functions that have a finding classification of <code>Optimized</code> don't have a finding reason code.</p>
    /// </note>
    /// <p>Finding reason codes for functions include:</p>
    /// <ul>
    /// <li>
    /// <p><b> <code>MemoryOverprovisioned</code> </b> — The function is over-provisioned when its memory configuration can be sized down while still meeting the performance requirements of your workload. An over-provisioned function might lead to unnecessary infrastructure cost. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>MemoryUnderprovisioned</code> </b> — The function is under-provisioned when its memory configuration doesn't meet the performance requirements of the workload. An under-provisioned function might lead to poor application performance. This finding reason code is part of the <code>NotOptimized</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>InsufficientData</code> </b> — The function does not have sufficient metric data for Compute Optimizer to generate a recommendation. For more information, see the <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/requirements.html">Supported resources and requirements</a> in the <i>Compute Optimizer User Guide</i>. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// <li>
    /// <p><b> <code>Inconclusive</code> </b> — The function does not qualify for a recommendation because Compute Optimizer cannot generate a recommendation with a high degree of confidence. This finding reason code is part of the <code>Unavailable</code> finding classification.</p></li>
    /// </ul>
    pub fn get_finding_reason_codes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionRecommendationFindingReasonCode>> {
        &self.finding_reason_codes
    }
    /// Appends an item to `memory_size_recommendation_options`.
    ///
    /// To override the contents of this collection use [`set_memory_size_recommendation_options`](Self::set_memory_size_recommendation_options).
    ///
    /// <p>An array of objects that describe the memory configuration recommendation options for the function.</p>
    pub fn memory_size_recommendation_options(mut self, input: crate::types::LambdaFunctionMemoryRecommendationOption) -> Self {
        let mut v = self.memory_size_recommendation_options.unwrap_or_default();
        v.push(input);
        self.memory_size_recommendation_options = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that describe the memory configuration recommendation options for the function.</p>
    pub fn set_memory_size_recommendation_options(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionMemoryRecommendationOption>>,
    ) -> Self {
        self.memory_size_recommendation_options = input;
        self
    }
    /// <p>An array of objects that describe the memory configuration recommendation options for the function.</p>
    pub fn get_memory_size_recommendation_options(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::LambdaFunctionMemoryRecommendationOption>> {
        &self.memory_size_recommendation_options
    }
    /// <p>The risk of the current Lambda function not meeting the performance needs of its workloads. The higher the risk, the more likely the current Lambda function requires more memory.</p>
    pub fn current_performance_risk(mut self, input: crate::types::CurrentPerformanceRisk) -> Self {
        self.current_performance_risk = ::std::option::Option::Some(input);
        self
    }
    /// <p>The risk of the current Lambda function not meeting the performance needs of its workloads. The higher the risk, the more likely the current Lambda function requires more memory.</p>
    pub fn set_current_performance_risk(mut self, input: ::std::option::Option<crate::types::CurrentPerformanceRisk>) -> Self {
        self.current_performance_risk = input;
        self
    }
    /// <p>The risk of the current Lambda function not meeting the performance needs of its workloads. The higher the risk, the more likely the current Lambda function requires more memory.</p>
    pub fn get_current_performance_risk(&self) -> &::std::option::Option<crate::types::CurrentPerformanceRisk> {
        &self.current_performance_risk
    }
    /// <p>Describes the effective recommendation preferences for Lambda functions.</p>
    pub fn effective_recommendation_preferences(mut self, input: crate::types::LambdaEffectiveRecommendationPreferences) -> Self {
        self.effective_recommendation_preferences = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the effective recommendation preferences for Lambda functions.</p>
    pub fn set_effective_recommendation_preferences(
        mut self,
        input: ::std::option::Option<crate::types::LambdaEffectiveRecommendationPreferences>,
    ) -> Self {
        self.effective_recommendation_preferences = input;
        self
    }
    /// <p>Describes the effective recommendation preferences for Lambda functions.</p>
    pub fn get_effective_recommendation_preferences(&self) -> &::std::option::Option<crate::types::LambdaEffectiveRecommendationPreferences> {
        &self.effective_recommendation_preferences
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags assigned to your Lambda function recommendations.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags assigned to your Lambda function recommendations.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags assigned to your Lambda function recommendations.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`LambdaFunctionRecommendation`](crate::types::LambdaFunctionRecommendation).
    pub fn build(self) -> crate::types::LambdaFunctionRecommendation {
        crate::types::LambdaFunctionRecommendation {
            function_arn: self.function_arn,
            function_version: self.function_version,
            account_id: self.account_id,
            current_memory_size: self.current_memory_size.unwrap_or_default(),
            number_of_invocations: self.number_of_invocations.unwrap_or_default(),
            utilization_metrics: self.utilization_metrics,
            lookback_period_in_days: self.lookback_period_in_days.unwrap_or_default(),
            last_refresh_timestamp: self.last_refresh_timestamp,
            finding: self.finding,
            finding_reason_codes: self.finding_reason_codes,
            memory_size_recommendation_options: self.memory_size_recommendation_options,
            current_performance_risk: self.current_performance_risk,
            effective_recommendation_preferences: self.effective_recommendation_preferences,
            tags: self.tags,
        }
    }
}
