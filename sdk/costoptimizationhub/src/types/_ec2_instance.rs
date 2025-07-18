// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the EC2 instance configuration of the current and recommended resource configuration for a recommendation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Ec2Instance {
    /// <p>The EC2 instance configuration used for recommendations.</p>
    pub configuration: ::std::option::Option<crate::types::Ec2InstanceConfiguration>,
    /// <p>Cost impact of the recommendation.</p>
    pub cost_calculation: ::std::option::Option<crate::types::ResourceCostCalculation>,
}
impl Ec2Instance {
    /// <p>The EC2 instance configuration used for recommendations.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::Ec2InstanceConfiguration> {
        self.configuration.as_ref()
    }
    /// <p>Cost impact of the recommendation.</p>
    pub fn cost_calculation(&self) -> ::std::option::Option<&crate::types::ResourceCostCalculation> {
        self.cost_calculation.as_ref()
    }
}
impl Ec2Instance {
    /// Creates a new builder-style object to manufacture [`Ec2Instance`](crate::types::Ec2Instance).
    pub fn builder() -> crate::types::builders::Ec2InstanceBuilder {
        crate::types::builders::Ec2InstanceBuilder::default()
    }
}

/// A builder for [`Ec2Instance`](crate::types::Ec2Instance).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Ec2InstanceBuilder {
    pub(crate) configuration: ::std::option::Option<crate::types::Ec2InstanceConfiguration>,
    pub(crate) cost_calculation: ::std::option::Option<crate::types::ResourceCostCalculation>,
}
impl Ec2InstanceBuilder {
    /// <p>The EC2 instance configuration used for recommendations.</p>
    pub fn configuration(mut self, input: crate::types::Ec2InstanceConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The EC2 instance configuration used for recommendations.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::Ec2InstanceConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>The EC2 instance configuration used for recommendations.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::Ec2InstanceConfiguration> {
        &self.configuration
    }
    /// <p>Cost impact of the recommendation.</p>
    pub fn cost_calculation(mut self, input: crate::types::ResourceCostCalculation) -> Self {
        self.cost_calculation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Cost impact of the recommendation.</p>
    pub fn set_cost_calculation(mut self, input: ::std::option::Option<crate::types::ResourceCostCalculation>) -> Self {
        self.cost_calculation = input;
        self
    }
    /// <p>Cost impact of the recommendation.</p>
    pub fn get_cost_calculation(&self) -> &::std::option::Option<crate::types::ResourceCostCalculation> {
        &self.cost_calculation
    }
    /// Consumes the builder and constructs a [`Ec2Instance`](crate::types::Ec2Instance).
    pub fn build(self) -> crate::types::Ec2Instance {
        crate::types::Ec2Instance {
            configuration: self.configuration,
            cost_calculation: self.cost_calculation,
        }
    }
}
