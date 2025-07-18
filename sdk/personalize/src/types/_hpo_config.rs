// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the properties for hyperparameter optimization (HPO).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HpoConfig {
    /// <p>The metric to optimize during HPO.</p><note>
    /// <p>Amazon Personalize doesn't support configuring the <code>hpoObjective</code> at this time.</p>
    /// </note>
    pub hpo_objective: ::std::option::Option<crate::types::HpoObjective>,
    /// <p>Describes the resource configuration for HPO.</p>
    pub hpo_resource_config: ::std::option::Option<crate::types::HpoResourceConfig>,
    /// <p>The hyperparameters and their allowable ranges.</p>
    pub algorithm_hyper_parameter_ranges: ::std::option::Option<crate::types::HyperParameterRanges>,
}
impl HpoConfig {
    /// <p>The metric to optimize during HPO.</p><note>
    /// <p>Amazon Personalize doesn't support configuring the <code>hpoObjective</code> at this time.</p>
    /// </note>
    pub fn hpo_objective(&self) -> ::std::option::Option<&crate::types::HpoObjective> {
        self.hpo_objective.as_ref()
    }
    /// <p>Describes the resource configuration for HPO.</p>
    pub fn hpo_resource_config(&self) -> ::std::option::Option<&crate::types::HpoResourceConfig> {
        self.hpo_resource_config.as_ref()
    }
    /// <p>The hyperparameters and their allowable ranges.</p>
    pub fn algorithm_hyper_parameter_ranges(&self) -> ::std::option::Option<&crate::types::HyperParameterRanges> {
        self.algorithm_hyper_parameter_ranges.as_ref()
    }
}
impl HpoConfig {
    /// Creates a new builder-style object to manufacture [`HpoConfig`](crate::types::HpoConfig).
    pub fn builder() -> crate::types::builders::HpoConfigBuilder {
        crate::types::builders::HpoConfigBuilder::default()
    }
}

/// A builder for [`HpoConfig`](crate::types::HpoConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HpoConfigBuilder {
    pub(crate) hpo_objective: ::std::option::Option<crate::types::HpoObjective>,
    pub(crate) hpo_resource_config: ::std::option::Option<crate::types::HpoResourceConfig>,
    pub(crate) algorithm_hyper_parameter_ranges: ::std::option::Option<crate::types::HyperParameterRanges>,
}
impl HpoConfigBuilder {
    /// <p>The metric to optimize during HPO.</p><note>
    /// <p>Amazon Personalize doesn't support configuring the <code>hpoObjective</code> at this time.</p>
    /// </note>
    pub fn hpo_objective(mut self, input: crate::types::HpoObjective) -> Self {
        self.hpo_objective = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metric to optimize during HPO.</p><note>
    /// <p>Amazon Personalize doesn't support configuring the <code>hpoObjective</code> at this time.</p>
    /// </note>
    pub fn set_hpo_objective(mut self, input: ::std::option::Option<crate::types::HpoObjective>) -> Self {
        self.hpo_objective = input;
        self
    }
    /// <p>The metric to optimize during HPO.</p><note>
    /// <p>Amazon Personalize doesn't support configuring the <code>hpoObjective</code> at this time.</p>
    /// </note>
    pub fn get_hpo_objective(&self) -> &::std::option::Option<crate::types::HpoObjective> {
        &self.hpo_objective
    }
    /// <p>Describes the resource configuration for HPO.</p>
    pub fn hpo_resource_config(mut self, input: crate::types::HpoResourceConfig) -> Self {
        self.hpo_resource_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the resource configuration for HPO.</p>
    pub fn set_hpo_resource_config(mut self, input: ::std::option::Option<crate::types::HpoResourceConfig>) -> Self {
        self.hpo_resource_config = input;
        self
    }
    /// <p>Describes the resource configuration for HPO.</p>
    pub fn get_hpo_resource_config(&self) -> &::std::option::Option<crate::types::HpoResourceConfig> {
        &self.hpo_resource_config
    }
    /// <p>The hyperparameters and their allowable ranges.</p>
    pub fn algorithm_hyper_parameter_ranges(mut self, input: crate::types::HyperParameterRanges) -> Self {
        self.algorithm_hyper_parameter_ranges = ::std::option::Option::Some(input);
        self
    }
    /// <p>The hyperparameters and their allowable ranges.</p>
    pub fn set_algorithm_hyper_parameter_ranges(mut self, input: ::std::option::Option<crate::types::HyperParameterRanges>) -> Self {
        self.algorithm_hyper_parameter_ranges = input;
        self
    }
    /// <p>The hyperparameters and their allowable ranges.</p>
    pub fn get_algorithm_hyper_parameter_ranges(&self) -> &::std::option::Option<crate::types::HyperParameterRanges> {
        &self.algorithm_hyper_parameter_ranges
    }
    /// Consumes the builder and constructs a [`HpoConfig`](crate::types::HpoConfig).
    pub fn build(self) -> crate::types::HpoConfig {
        crate::types::HpoConfig {
            hpo_objective: self.hpo_objective,
            hpo_resource_config: self.hpo_resource_config,
            algorithm_hyper_parameter_ranges: self.algorithm_hyper_parameter_ranges,
        }
    }
}
