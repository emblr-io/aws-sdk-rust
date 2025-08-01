// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a recommendation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecommendationItem {
    /// <p>Identifier of the resource.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>Identifier of the target account.</p>
    pub target_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The target region.</p>
    pub target_region: ::std::option::Option<::std::string::String>,
    /// <p>Specifies if the recommendation has already been implemented.</p>
    pub already_implemented: ::std::option::Option<bool>,
    /// <p>Indicates if an operational recommendation item is excluded.</p>
    pub excluded: ::std::option::Option<bool>,
    /// <p>Indicates the reason for excluding an operational recommendation.</p>
    pub exclude_reason: ::std::option::Option<crate::types::ExcludeRecommendationReason>,
    /// <p>Indicates the experiment created in FIS that was discovered by Resilience Hub, which matches the recommendation.</p>
    pub latest_discovered_experiment: ::std::option::Option<crate::types::Experiment>,
    /// <p>Indicates the previously implemented Amazon CloudWatch alarm discovered by Resilience Hub.</p>
    pub discovered_alarm: ::std::option::Option<crate::types::Alarm>,
}
impl RecommendationItem {
    /// <p>Identifier of the resource.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>Identifier of the target account.</p>
    pub fn target_account_id(&self) -> ::std::option::Option<&str> {
        self.target_account_id.as_deref()
    }
    /// <p>The target region.</p>
    pub fn target_region(&self) -> ::std::option::Option<&str> {
        self.target_region.as_deref()
    }
    /// <p>Specifies if the recommendation has already been implemented.</p>
    pub fn already_implemented(&self) -> ::std::option::Option<bool> {
        self.already_implemented
    }
    /// <p>Indicates if an operational recommendation item is excluded.</p>
    pub fn excluded(&self) -> ::std::option::Option<bool> {
        self.excluded
    }
    /// <p>Indicates the reason for excluding an operational recommendation.</p>
    pub fn exclude_reason(&self) -> ::std::option::Option<&crate::types::ExcludeRecommendationReason> {
        self.exclude_reason.as_ref()
    }
    /// <p>Indicates the experiment created in FIS that was discovered by Resilience Hub, which matches the recommendation.</p>
    pub fn latest_discovered_experiment(&self) -> ::std::option::Option<&crate::types::Experiment> {
        self.latest_discovered_experiment.as_ref()
    }
    /// <p>Indicates the previously implemented Amazon CloudWatch alarm discovered by Resilience Hub.</p>
    pub fn discovered_alarm(&self) -> ::std::option::Option<&crate::types::Alarm> {
        self.discovered_alarm.as_ref()
    }
}
impl RecommendationItem {
    /// Creates a new builder-style object to manufacture [`RecommendationItem`](crate::types::RecommendationItem).
    pub fn builder() -> crate::types::builders::RecommendationItemBuilder {
        crate::types::builders::RecommendationItemBuilder::default()
    }
}

/// A builder for [`RecommendationItem`](crate::types::RecommendationItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecommendationItemBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) target_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) target_region: ::std::option::Option<::std::string::String>,
    pub(crate) already_implemented: ::std::option::Option<bool>,
    pub(crate) excluded: ::std::option::Option<bool>,
    pub(crate) exclude_reason: ::std::option::Option<crate::types::ExcludeRecommendationReason>,
    pub(crate) latest_discovered_experiment: ::std::option::Option<crate::types::Experiment>,
    pub(crate) discovered_alarm: ::std::option::Option<crate::types::Alarm>,
}
impl RecommendationItemBuilder {
    /// <p>Identifier of the resource.</p>
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier of the resource.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>Identifier of the resource.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>Identifier of the target account.</p>
    pub fn target_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier of the target account.</p>
    pub fn set_target_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_account_id = input;
        self
    }
    /// <p>Identifier of the target account.</p>
    pub fn get_target_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_account_id
    }
    /// <p>The target region.</p>
    pub fn target_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The target region.</p>
    pub fn set_target_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_region = input;
        self
    }
    /// <p>The target region.</p>
    pub fn get_target_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_region
    }
    /// <p>Specifies if the recommendation has already been implemented.</p>
    pub fn already_implemented(mut self, input: bool) -> Self {
        self.already_implemented = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if the recommendation has already been implemented.</p>
    pub fn set_already_implemented(mut self, input: ::std::option::Option<bool>) -> Self {
        self.already_implemented = input;
        self
    }
    /// <p>Specifies if the recommendation has already been implemented.</p>
    pub fn get_already_implemented(&self) -> &::std::option::Option<bool> {
        &self.already_implemented
    }
    /// <p>Indicates if an operational recommendation item is excluded.</p>
    pub fn excluded(mut self, input: bool) -> Self {
        self.excluded = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if an operational recommendation item is excluded.</p>
    pub fn set_excluded(mut self, input: ::std::option::Option<bool>) -> Self {
        self.excluded = input;
        self
    }
    /// <p>Indicates if an operational recommendation item is excluded.</p>
    pub fn get_excluded(&self) -> &::std::option::Option<bool> {
        &self.excluded
    }
    /// <p>Indicates the reason for excluding an operational recommendation.</p>
    pub fn exclude_reason(mut self, input: crate::types::ExcludeRecommendationReason) -> Self {
        self.exclude_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the reason for excluding an operational recommendation.</p>
    pub fn set_exclude_reason(mut self, input: ::std::option::Option<crate::types::ExcludeRecommendationReason>) -> Self {
        self.exclude_reason = input;
        self
    }
    /// <p>Indicates the reason for excluding an operational recommendation.</p>
    pub fn get_exclude_reason(&self) -> &::std::option::Option<crate::types::ExcludeRecommendationReason> {
        &self.exclude_reason
    }
    /// <p>Indicates the experiment created in FIS that was discovered by Resilience Hub, which matches the recommendation.</p>
    pub fn latest_discovered_experiment(mut self, input: crate::types::Experiment) -> Self {
        self.latest_discovered_experiment = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the experiment created in FIS that was discovered by Resilience Hub, which matches the recommendation.</p>
    pub fn set_latest_discovered_experiment(mut self, input: ::std::option::Option<crate::types::Experiment>) -> Self {
        self.latest_discovered_experiment = input;
        self
    }
    /// <p>Indicates the experiment created in FIS that was discovered by Resilience Hub, which matches the recommendation.</p>
    pub fn get_latest_discovered_experiment(&self) -> &::std::option::Option<crate::types::Experiment> {
        &self.latest_discovered_experiment
    }
    /// <p>Indicates the previously implemented Amazon CloudWatch alarm discovered by Resilience Hub.</p>
    pub fn discovered_alarm(mut self, input: crate::types::Alarm) -> Self {
        self.discovered_alarm = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the previously implemented Amazon CloudWatch alarm discovered by Resilience Hub.</p>
    pub fn set_discovered_alarm(mut self, input: ::std::option::Option<crate::types::Alarm>) -> Self {
        self.discovered_alarm = input;
        self
    }
    /// <p>Indicates the previously implemented Amazon CloudWatch alarm discovered by Resilience Hub.</p>
    pub fn get_discovered_alarm(&self) -> &::std::option::Option<crate::types::Alarm> {
        &self.discovered_alarm
    }
    /// Consumes the builder and constructs a [`RecommendationItem`](crate::types::RecommendationItem).
    pub fn build(self) -> crate::types::RecommendationItem {
        crate::types::RecommendationItem {
            resource_id: self.resource_id,
            target_account_id: self.target_account_id,
            target_region: self.target_region,
            already_implemented: self.already_implemented,
            excluded: self.excluded,
            exclude_reason: self.exclude_reason,
            latest_discovered_experiment: self.latest_discovered_experiment,
            discovered_alarm: self.discovered_alarm,
        }
    }
}
