// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Cost impact of the purchase recommendation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SavingsPlansCostCalculation {
    /// <p>Pricing details of the purchase recommendation.</p>
    pub pricing: ::std::option::Option<crate::types::SavingsPlansPricing>,
}
impl SavingsPlansCostCalculation {
    /// <p>Pricing details of the purchase recommendation.</p>
    pub fn pricing(&self) -> ::std::option::Option<&crate::types::SavingsPlansPricing> {
        self.pricing.as_ref()
    }
}
impl SavingsPlansCostCalculation {
    /// Creates a new builder-style object to manufacture [`SavingsPlansCostCalculation`](crate::types::SavingsPlansCostCalculation).
    pub fn builder() -> crate::types::builders::SavingsPlansCostCalculationBuilder {
        crate::types::builders::SavingsPlansCostCalculationBuilder::default()
    }
}

/// A builder for [`SavingsPlansCostCalculation`](crate::types::SavingsPlansCostCalculation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SavingsPlansCostCalculationBuilder {
    pub(crate) pricing: ::std::option::Option<crate::types::SavingsPlansPricing>,
}
impl SavingsPlansCostCalculationBuilder {
    /// <p>Pricing details of the purchase recommendation.</p>
    pub fn pricing(mut self, input: crate::types::SavingsPlansPricing) -> Self {
        self.pricing = ::std::option::Option::Some(input);
        self
    }
    /// <p>Pricing details of the purchase recommendation.</p>
    pub fn set_pricing(mut self, input: ::std::option::Option<crate::types::SavingsPlansPricing>) -> Self {
        self.pricing = input;
        self
    }
    /// <p>Pricing details of the purchase recommendation.</p>
    pub fn get_pricing(&self) -> &::std::option::Option<crate::types::SavingsPlansPricing> {
        &self.pricing
    }
    /// Consumes the builder and constructs a [`SavingsPlansCostCalculation`](crate::types::SavingsPlansCostCalculation).
    pub fn build(self) -> crate::types::SavingsPlansCostCalculation {
        crate::types::SavingsPlansCostCalculation { pricing: self.pricing }
    }
}
