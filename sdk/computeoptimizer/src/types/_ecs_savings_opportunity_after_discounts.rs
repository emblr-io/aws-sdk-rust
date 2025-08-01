// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the savings opportunity for Amazon ECS service recommendations after applying Savings Plans discounts.</p>
/// <p>Savings opportunity represents the estimated monthly savings after applying Savings Plans discounts. You can achieve this by implementing a given Compute Optimizer recommendation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EcsSavingsOpportunityAfterDiscounts {
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub savings_opportunity_percentage: f64,
    /// <p>The estimated monthly savings possible by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub estimated_monthly_savings: ::std::option::Option<crate::types::EcsEstimatedMonthlySavings>,
}
impl EcsSavingsOpportunityAfterDiscounts {
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub fn savings_opportunity_percentage(&self) -> f64 {
        self.savings_opportunity_percentage
    }
    /// <p>The estimated monthly savings possible by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub fn estimated_monthly_savings(&self) -> ::std::option::Option<&crate::types::EcsEstimatedMonthlySavings> {
        self.estimated_monthly_savings.as_ref()
    }
}
impl EcsSavingsOpportunityAfterDiscounts {
    /// Creates a new builder-style object to manufacture [`EcsSavingsOpportunityAfterDiscounts`](crate::types::EcsSavingsOpportunityAfterDiscounts).
    pub fn builder() -> crate::types::builders::EcsSavingsOpportunityAfterDiscountsBuilder {
        crate::types::builders::EcsSavingsOpportunityAfterDiscountsBuilder::default()
    }
}

/// A builder for [`EcsSavingsOpportunityAfterDiscounts`](crate::types::EcsSavingsOpportunityAfterDiscounts).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EcsSavingsOpportunityAfterDiscountsBuilder {
    pub(crate) savings_opportunity_percentage: ::std::option::Option<f64>,
    pub(crate) estimated_monthly_savings: ::std::option::Option<crate::types::EcsEstimatedMonthlySavings>,
}
impl EcsSavingsOpportunityAfterDiscountsBuilder {
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub fn savings_opportunity_percentage(mut self, input: f64) -> Self {
        self.savings_opportunity_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub fn set_savings_opportunity_percentage(mut self, input: ::std::option::Option<f64>) -> Self {
        self.savings_opportunity_percentage = input;
        self
    }
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub fn get_savings_opportunity_percentage(&self) -> &::std::option::Option<f64> {
        &self.savings_opportunity_percentage
    }
    /// <p>The estimated monthly savings possible by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub fn estimated_monthly_savings(mut self, input: crate::types::EcsEstimatedMonthlySavings) -> Self {
        self.estimated_monthly_savings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The estimated monthly savings possible by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub fn set_estimated_monthly_savings(mut self, input: ::std::option::Option<crate::types::EcsEstimatedMonthlySavings>) -> Self {
        self.estimated_monthly_savings = input;
        self
    }
    /// <p>The estimated monthly savings possible by adopting Compute Optimizer’s Amazon ECS service recommendations. This includes any applicable Savings Plans discounts.</p>
    pub fn get_estimated_monthly_savings(&self) -> &::std::option::Option<crate::types::EcsEstimatedMonthlySavings> {
        &self.estimated_monthly_savings
    }
    /// Consumes the builder and constructs a [`EcsSavingsOpportunityAfterDiscounts`](crate::types::EcsSavingsOpportunityAfterDiscounts).
    pub fn build(self) -> crate::types::EcsSavingsOpportunityAfterDiscounts {
        crate::types::EcsSavingsOpportunityAfterDiscounts {
            savings_opportunity_percentage: self.savings_opportunity_percentage.unwrap_or_default(),
            estimated_monthly_savings: self.estimated_monthly_savings,
        }
    }
}
