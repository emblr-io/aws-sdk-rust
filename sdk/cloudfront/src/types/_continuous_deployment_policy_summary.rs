// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of the information about your continuous deployment policies.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContinuousDeploymentPolicySummary {
    /// <p>The continuous deployment policy.</p>
    pub continuous_deployment_policy: ::std::option::Option<crate::types::ContinuousDeploymentPolicy>,
}
impl ContinuousDeploymentPolicySummary {
    /// <p>The continuous deployment policy.</p>
    pub fn continuous_deployment_policy(&self) -> ::std::option::Option<&crate::types::ContinuousDeploymentPolicy> {
        self.continuous_deployment_policy.as_ref()
    }
}
impl ContinuousDeploymentPolicySummary {
    /// Creates a new builder-style object to manufacture [`ContinuousDeploymentPolicySummary`](crate::types::ContinuousDeploymentPolicySummary).
    pub fn builder() -> crate::types::builders::ContinuousDeploymentPolicySummaryBuilder {
        crate::types::builders::ContinuousDeploymentPolicySummaryBuilder::default()
    }
}

/// A builder for [`ContinuousDeploymentPolicySummary`](crate::types::ContinuousDeploymentPolicySummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContinuousDeploymentPolicySummaryBuilder {
    pub(crate) continuous_deployment_policy: ::std::option::Option<crate::types::ContinuousDeploymentPolicy>,
}
impl ContinuousDeploymentPolicySummaryBuilder {
    /// <p>The continuous deployment policy.</p>
    /// This field is required.
    pub fn continuous_deployment_policy(mut self, input: crate::types::ContinuousDeploymentPolicy) -> Self {
        self.continuous_deployment_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The continuous deployment policy.</p>
    pub fn set_continuous_deployment_policy(mut self, input: ::std::option::Option<crate::types::ContinuousDeploymentPolicy>) -> Self {
        self.continuous_deployment_policy = input;
        self
    }
    /// <p>The continuous deployment policy.</p>
    pub fn get_continuous_deployment_policy(&self) -> &::std::option::Option<crate::types::ContinuousDeploymentPolicy> {
        &self.continuous_deployment_policy
    }
    /// Consumes the builder and constructs a [`ContinuousDeploymentPolicySummary`](crate::types::ContinuousDeploymentPolicySummary).
    pub fn build(self) -> crate::types::ContinuousDeploymentPolicySummary {
        crate::types::ContinuousDeploymentPolicySummary {
            continuous_deployment_policy: self.continuous_deployment_policy,
        }
    }
}
