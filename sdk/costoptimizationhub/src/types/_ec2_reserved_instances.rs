// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The EC2 reserved instances recommendation details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Ec2ReservedInstances {
    /// <p>The EC2 reserved instances configuration used for recommendations.</p>
    pub configuration: ::std::option::Option<crate::types::Ec2ReservedInstancesConfiguration>,
    /// <p>Cost impact of the purchase recommendation.</p>
    pub cost_calculation: ::std::option::Option<crate::types::ReservedInstancesCostCalculation>,
}
impl Ec2ReservedInstances {
    /// <p>The EC2 reserved instances configuration used for recommendations.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::Ec2ReservedInstancesConfiguration> {
        self.configuration.as_ref()
    }
    /// <p>Cost impact of the purchase recommendation.</p>
    pub fn cost_calculation(&self) -> ::std::option::Option<&crate::types::ReservedInstancesCostCalculation> {
        self.cost_calculation.as_ref()
    }
}
impl Ec2ReservedInstances {
    /// Creates a new builder-style object to manufacture [`Ec2ReservedInstances`](crate::types::Ec2ReservedInstances).
    pub fn builder() -> crate::types::builders::Ec2ReservedInstancesBuilder {
        crate::types::builders::Ec2ReservedInstancesBuilder::default()
    }
}

/// A builder for [`Ec2ReservedInstances`](crate::types::Ec2ReservedInstances).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Ec2ReservedInstancesBuilder {
    pub(crate) configuration: ::std::option::Option<crate::types::Ec2ReservedInstancesConfiguration>,
    pub(crate) cost_calculation: ::std::option::Option<crate::types::ReservedInstancesCostCalculation>,
}
impl Ec2ReservedInstancesBuilder {
    /// <p>The EC2 reserved instances configuration used for recommendations.</p>
    pub fn configuration(mut self, input: crate::types::Ec2ReservedInstancesConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The EC2 reserved instances configuration used for recommendations.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::Ec2ReservedInstancesConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>The EC2 reserved instances configuration used for recommendations.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::Ec2ReservedInstancesConfiguration> {
        &self.configuration
    }
    /// <p>Cost impact of the purchase recommendation.</p>
    pub fn cost_calculation(mut self, input: crate::types::ReservedInstancesCostCalculation) -> Self {
        self.cost_calculation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Cost impact of the purchase recommendation.</p>
    pub fn set_cost_calculation(mut self, input: ::std::option::Option<crate::types::ReservedInstancesCostCalculation>) -> Self {
        self.cost_calculation = input;
        self
    }
    /// <p>Cost impact of the purchase recommendation.</p>
    pub fn get_cost_calculation(&self) -> &::std::option::Option<crate::types::ReservedInstancesCostCalculation> {
        &self.cost_calculation
    }
    /// Consumes the builder and constructs a [`Ec2ReservedInstances`](crate::types::Ec2ReservedInstances).
    pub fn build(self) -> crate::types::Ec2ReservedInstances {
        crate::types::Ec2ReservedInstances {
            configuration: self.configuration,
            cost_calculation: self.cost_calculation,
        }
    }
}
