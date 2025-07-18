// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the details of an Aurora DB cluster storage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AuroraDbClusterStorage {
    /// <p>The Aurora DB cluster storage configuration used for recommendations.</p>
    pub configuration: ::std::option::Option<crate::types::AuroraDbClusterStorageConfiguration>,
    /// <p>Cost impact of the resource recommendation.</p>
    pub cost_calculation: ::std::option::Option<crate::types::ResourceCostCalculation>,
}
impl AuroraDbClusterStorage {
    /// <p>The Aurora DB cluster storage configuration used for recommendations.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::AuroraDbClusterStorageConfiguration> {
        self.configuration.as_ref()
    }
    /// <p>Cost impact of the resource recommendation.</p>
    pub fn cost_calculation(&self) -> ::std::option::Option<&crate::types::ResourceCostCalculation> {
        self.cost_calculation.as_ref()
    }
}
impl AuroraDbClusterStorage {
    /// Creates a new builder-style object to manufacture [`AuroraDbClusterStorage`](crate::types::AuroraDbClusterStorage).
    pub fn builder() -> crate::types::builders::AuroraDbClusterStorageBuilder {
        crate::types::builders::AuroraDbClusterStorageBuilder::default()
    }
}

/// A builder for [`AuroraDbClusterStorage`](crate::types::AuroraDbClusterStorage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AuroraDbClusterStorageBuilder {
    pub(crate) configuration: ::std::option::Option<crate::types::AuroraDbClusterStorageConfiguration>,
    pub(crate) cost_calculation: ::std::option::Option<crate::types::ResourceCostCalculation>,
}
impl AuroraDbClusterStorageBuilder {
    /// <p>The Aurora DB cluster storage configuration used for recommendations.</p>
    pub fn configuration(mut self, input: crate::types::AuroraDbClusterStorageConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Aurora DB cluster storage configuration used for recommendations.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::AuroraDbClusterStorageConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>The Aurora DB cluster storage configuration used for recommendations.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::AuroraDbClusterStorageConfiguration> {
        &self.configuration
    }
    /// <p>Cost impact of the resource recommendation.</p>
    pub fn cost_calculation(mut self, input: crate::types::ResourceCostCalculation) -> Self {
        self.cost_calculation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Cost impact of the resource recommendation.</p>
    pub fn set_cost_calculation(mut self, input: ::std::option::Option<crate::types::ResourceCostCalculation>) -> Self {
        self.cost_calculation = input;
        self
    }
    /// <p>Cost impact of the resource recommendation.</p>
    pub fn get_cost_calculation(&self) -> &::std::option::Option<crate::types::ResourceCostCalculation> {
        &self.cost_calculation
    }
    /// Consumes the builder and constructs a [`AuroraDbClusterStorage`](crate::types::AuroraDbClusterStorage).
    pub fn build(self) -> crate::types::AuroraDbClusterStorage {
        crate::types::AuroraDbClusterStorage {
            configuration: self.configuration,
            cost_calculation: self.cost_calculation,
        }
    }
}
