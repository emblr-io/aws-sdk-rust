// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEffectiveRecommendationPreferencesOutput {
    /// <p>The status of the enhanced infrastructure metrics recommendation preference. Considers all applicable preferences that you might have set at the resource, account, and organization level.</p>
    /// <p>A status of <code>Active</code> confirms that the preference is applied in the latest recommendation refresh, and a status of <code>Inactive</code> confirms that it's not yet applied to recommendations.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetAutoScalingGroupRecommendations</code> and <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/enhanced-infrastructure-metrics.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub enhanced_infrastructure_metrics: ::std::option::Option<crate::types::EnhancedInfrastructureMetrics>,
    /// <p>The provider of the external metrics recommendation preference. Considers all applicable preferences that you might have set at the account and organization level.</p>
    /// <p>If the preference is applied in the latest recommendation refresh, an object with a valid <code>source</code> value appears in the response. If the preference isn't applied to the recommendations already, then this object doesn't appear in the response.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/external-metrics-ingestion.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub external_metrics_preference: ::std::option::Option<crate::types::ExternalMetricsPreference>,
    /// <p>The number of days the utilization metrics of the Amazon Web Services resource are analyzed.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub look_back_period: ::std::option::Option<crate::types::LookBackPeriodPreference>,
    /// <p>The resource’s CPU and memory utilization preferences, such as threshold and headroom, that were used to generate rightsizing recommendations. It considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub utilization_preferences: ::std::option::Option<::std::vec::Vec<crate::types::UtilizationPreference>>,
    /// <p>The resource type values that are considered as candidates when generating rightsizing recommendations. This object resolves any wildcard expressions and returns the effective list of candidate resource type values. It also considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub preferred_resources: ::std::option::Option<::std::vec::Vec<crate::types::EffectivePreferredResource>>,
    _request_id: Option<String>,
}
impl GetEffectiveRecommendationPreferencesOutput {
    /// <p>The status of the enhanced infrastructure metrics recommendation preference. Considers all applicable preferences that you might have set at the resource, account, and organization level.</p>
    /// <p>A status of <code>Active</code> confirms that the preference is applied in the latest recommendation refresh, and a status of <code>Inactive</code> confirms that it's not yet applied to recommendations.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetAutoScalingGroupRecommendations</code> and <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/enhanced-infrastructure-metrics.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn enhanced_infrastructure_metrics(&self) -> ::std::option::Option<&crate::types::EnhancedInfrastructureMetrics> {
        self.enhanced_infrastructure_metrics.as_ref()
    }
    /// <p>The provider of the external metrics recommendation preference. Considers all applicable preferences that you might have set at the account and organization level.</p>
    /// <p>If the preference is applied in the latest recommendation refresh, an object with a valid <code>source</code> value appears in the response. If the preference isn't applied to the recommendations already, then this object doesn't appear in the response.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/external-metrics-ingestion.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn external_metrics_preference(&self) -> ::std::option::Option<&crate::types::ExternalMetricsPreference> {
        self.external_metrics_preference.as_ref()
    }
    /// <p>The number of days the utilization metrics of the Amazon Web Services resource are analyzed.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn look_back_period(&self) -> ::std::option::Option<&crate::types::LookBackPeriodPreference> {
        self.look_back_period.as_ref()
    }
    /// <p>The resource’s CPU and memory utilization preferences, such as threshold and headroom, that were used to generate rightsizing recommendations. It considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.utilization_preferences.is_none()`.
    pub fn utilization_preferences(&self) -> &[crate::types::UtilizationPreference] {
        self.utilization_preferences.as_deref().unwrap_or_default()
    }
    /// <p>The resource type values that are considered as candidates when generating rightsizing recommendations. This object resolves any wildcard expressions and returns the effective list of candidate resource type values. It also considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.preferred_resources.is_none()`.
    pub fn preferred_resources(&self) -> &[crate::types::EffectivePreferredResource] {
        self.preferred_resources.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetEffectiveRecommendationPreferencesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetEffectiveRecommendationPreferencesOutput {
    /// Creates a new builder-style object to manufacture [`GetEffectiveRecommendationPreferencesOutput`](crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesOutput).
    pub fn builder() -> crate::operation::get_effective_recommendation_preferences::builders::GetEffectiveRecommendationPreferencesOutputBuilder {
        crate::operation::get_effective_recommendation_preferences::builders::GetEffectiveRecommendationPreferencesOutputBuilder::default()
    }
}

/// A builder for [`GetEffectiveRecommendationPreferencesOutput`](crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEffectiveRecommendationPreferencesOutputBuilder {
    pub(crate) enhanced_infrastructure_metrics: ::std::option::Option<crate::types::EnhancedInfrastructureMetrics>,
    pub(crate) external_metrics_preference: ::std::option::Option<crate::types::ExternalMetricsPreference>,
    pub(crate) look_back_period: ::std::option::Option<crate::types::LookBackPeriodPreference>,
    pub(crate) utilization_preferences: ::std::option::Option<::std::vec::Vec<crate::types::UtilizationPreference>>,
    pub(crate) preferred_resources: ::std::option::Option<::std::vec::Vec<crate::types::EffectivePreferredResource>>,
    _request_id: Option<String>,
}
impl GetEffectiveRecommendationPreferencesOutputBuilder {
    /// <p>The status of the enhanced infrastructure metrics recommendation preference. Considers all applicable preferences that you might have set at the resource, account, and organization level.</p>
    /// <p>A status of <code>Active</code> confirms that the preference is applied in the latest recommendation refresh, and a status of <code>Inactive</code> confirms that it's not yet applied to recommendations.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetAutoScalingGroupRecommendations</code> and <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/enhanced-infrastructure-metrics.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn enhanced_infrastructure_metrics(mut self, input: crate::types::EnhancedInfrastructureMetrics) -> Self {
        self.enhanced_infrastructure_metrics = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the enhanced infrastructure metrics recommendation preference. Considers all applicable preferences that you might have set at the resource, account, and organization level.</p>
    /// <p>A status of <code>Active</code> confirms that the preference is applied in the latest recommendation refresh, and a status of <code>Inactive</code> confirms that it's not yet applied to recommendations.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetAutoScalingGroupRecommendations</code> and <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/enhanced-infrastructure-metrics.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn set_enhanced_infrastructure_metrics(mut self, input: ::std::option::Option<crate::types::EnhancedInfrastructureMetrics>) -> Self {
        self.enhanced_infrastructure_metrics = input;
        self
    }
    /// <p>The status of the enhanced infrastructure metrics recommendation preference. Considers all applicable preferences that you might have set at the resource, account, and organization level.</p>
    /// <p>A status of <code>Active</code> confirms that the preference is applied in the latest recommendation refresh, and a status of <code>Inactive</code> confirms that it's not yet applied to recommendations.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetAutoScalingGroupRecommendations</code> and <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/enhanced-infrastructure-metrics.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn get_enhanced_infrastructure_metrics(&self) -> &::std::option::Option<crate::types::EnhancedInfrastructureMetrics> {
        &self.enhanced_infrastructure_metrics
    }
    /// <p>The provider of the external metrics recommendation preference. Considers all applicable preferences that you might have set at the account and organization level.</p>
    /// <p>If the preference is applied in the latest recommendation refresh, an object with a valid <code>source</code> value appears in the response. If the preference isn't applied to the recommendations already, then this object doesn't appear in the response.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/external-metrics-ingestion.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn external_metrics_preference(mut self, input: crate::types::ExternalMetricsPreference) -> Self {
        self.external_metrics_preference = ::std::option::Option::Some(input);
        self
    }
    /// <p>The provider of the external metrics recommendation preference. Considers all applicable preferences that you might have set at the account and organization level.</p>
    /// <p>If the preference is applied in the latest recommendation refresh, an object with a valid <code>source</code> value appears in the response. If the preference isn't applied to the recommendations already, then this object doesn't appear in the response.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/external-metrics-ingestion.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn set_external_metrics_preference(mut self, input: ::std::option::Option<crate::types::ExternalMetricsPreference>) -> Self {
        self.external_metrics_preference = input;
        self
    }
    /// <p>The provider of the external metrics recommendation preference. Considers all applicable preferences that you might have set at the account and organization level.</p>
    /// <p>If the preference is applied in the latest recommendation refresh, an object with a valid <code>source</code> value appears in the response. If the preference isn't applied to the recommendations already, then this object doesn't appear in the response.</p>
    /// <p>To validate whether the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the <code>GetEC2InstanceRecommendations</code> actions.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/external-metrics-ingestion.html">Enhanced infrastructure metrics</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn get_external_metrics_preference(&self) -> &::std::option::Option<crate::types::ExternalMetricsPreference> {
        &self.external_metrics_preference
    }
    /// <p>The number of days the utilization metrics of the Amazon Web Services resource are analyzed.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn look_back_period(mut self, input: crate::types::LookBackPeriodPreference) -> Self {
        self.look_back_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of days the utilization metrics of the Amazon Web Services resource are analyzed.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn set_look_back_period(mut self, input: ::std::option::Option<crate::types::LookBackPeriodPreference>) -> Self {
        self.look_back_period = input;
        self
    }
    /// <p>The number of days the utilization metrics of the Amazon Web Services resource are analyzed.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn get_look_back_period(&self) -> &::std::option::Option<crate::types::LookBackPeriodPreference> {
        &self.look_back_period
    }
    /// Appends an item to `utilization_preferences`.
    ///
    /// To override the contents of this collection use [`set_utilization_preferences`](Self::set_utilization_preferences).
    ///
    /// <p>The resource’s CPU and memory utilization preferences, such as threshold and headroom, that were used to generate rightsizing recommendations. It considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn utilization_preferences(mut self, input: crate::types::UtilizationPreference) -> Self {
        let mut v = self.utilization_preferences.unwrap_or_default();
        v.push(input);
        self.utilization_preferences = ::std::option::Option::Some(v);
        self
    }
    /// <p>The resource’s CPU and memory utilization preferences, such as threshold and headroom, that were used to generate rightsizing recommendations. It considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn set_utilization_preferences(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UtilizationPreference>>) -> Self {
        self.utilization_preferences = input;
        self
    }
    /// <p>The resource’s CPU and memory utilization preferences, such as threshold and headroom, that were used to generate rightsizing recommendations. It considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn get_utilization_preferences(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UtilizationPreference>> {
        &self.utilization_preferences
    }
    /// Appends an item to `preferred_resources`.
    ///
    /// To override the contents of this collection use [`set_preferred_resources`](Self::set_preferred_resources).
    ///
    /// <p>The resource type values that are considered as candidates when generating rightsizing recommendations. This object resolves any wildcard expressions and returns the effective list of candidate resource type values. It also considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn preferred_resources(mut self, input: crate::types::EffectivePreferredResource) -> Self {
        let mut v = self.preferred_resources.unwrap_or_default();
        v.push(input);
        self.preferred_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The resource type values that are considered as candidates when generating rightsizing recommendations. This object resolves any wildcard expressions and returns the effective list of candidate resource type values. It also considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn set_preferred_resources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EffectivePreferredResource>>) -> Self {
        self.preferred_resources = input;
        self
    }
    /// <p>The resource type values that are considered as candidates when generating rightsizing recommendations. This object resolves any wildcard expressions and returns the effective list of candidate resource type values. It also considers all applicable preferences that you set at the resource, account, and organization level.</p>
    /// <p>To validate that the preference is applied to your last generated set of recommendations, review the <code>effectiveRecommendationPreferences</code> value in the response of the GetAutoScalingGroupRecommendations or GetEC2InstanceRecommendations actions.</p>
    pub fn get_preferred_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EffectivePreferredResource>> {
        &self.preferred_resources
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetEffectiveRecommendationPreferencesOutput`](crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesOutput).
    pub fn build(self) -> crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesOutput {
        crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesOutput {
            enhanced_infrastructure_metrics: self.enhanced_infrastructure_metrics,
            external_metrics_preference: self.external_metrics_preference,
            look_back_period: self.look_back_period,
            utilization_preferences: self.utilization_preferences,
            preferred_resources: self.preferred_resources,
            _request_id: self._request_id,
        }
    }
}
