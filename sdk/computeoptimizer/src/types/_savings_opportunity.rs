// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the savings opportunity for recommendations of a given resource type or for the recommendation option of an individual resource.</p>
/// <p>Savings opportunity represents the estimated monthly savings you can achieve by implementing a given Compute Optimizer recommendation.</p><important>
/// <p>Savings opportunity data requires that you opt in to Cost Explorer, as well as activate <b>Receive Amazon EC2 resource recommendations</b> in the Cost Explorer preferences page. That creates a connection between Cost Explorer and Compute Optimizer. With this connection, Cost Explorer generates savings estimates considering the price of existing resources, the price of recommended resources, and historical usage data. Estimated monthly savings reflects the projected dollar savings associated with each of the recommendations generated. For more information, see <a href="https://docs.aws.amazon.com/cost-management/latest/userguide/ce-enable.html">Enabling Cost Explorer</a> and <a href="https://docs.aws.amazon.com/cost-management/latest/userguide/ce-rightsizing.html">Optimizing your cost with Rightsizing Recommendations</a> in the <i>Cost Management User Guide</i>.</p>
/// </important>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SavingsOpportunity {
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer recommendations for a given resource.</p>
    pub savings_opportunity_percentage: f64,
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing..</p>
    pub estimated_monthly_savings: ::std::option::Option<crate::types::EstimatedMonthlySavings>,
}
impl SavingsOpportunity {
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer recommendations for a given resource.</p>
    pub fn savings_opportunity_percentage(&self) -> f64 {
        self.savings_opportunity_percentage
    }
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing..</p>
    pub fn estimated_monthly_savings(&self) -> ::std::option::Option<&crate::types::EstimatedMonthlySavings> {
        self.estimated_monthly_savings.as_ref()
    }
}
impl SavingsOpportunity {
    /// Creates a new builder-style object to manufacture [`SavingsOpportunity`](crate::types::SavingsOpportunity).
    pub fn builder() -> crate::types::builders::SavingsOpportunityBuilder {
        crate::types::builders::SavingsOpportunityBuilder::default()
    }
}

/// A builder for [`SavingsOpportunity`](crate::types::SavingsOpportunity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SavingsOpportunityBuilder {
    pub(crate) savings_opportunity_percentage: ::std::option::Option<f64>,
    pub(crate) estimated_monthly_savings: ::std::option::Option<crate::types::EstimatedMonthlySavings>,
}
impl SavingsOpportunityBuilder {
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer recommendations for a given resource.</p>
    pub fn savings_opportunity_percentage(mut self, input: f64) -> Self {
        self.savings_opportunity_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer recommendations for a given resource.</p>
    pub fn set_savings_opportunity_percentage(mut self, input: ::std::option::Option<f64>) -> Self {
        self.savings_opportunity_percentage = input;
        self
    }
    /// <p>The estimated monthly savings possible as a percentage of monthly cost by adopting Compute Optimizer recommendations for a given resource.</p>
    pub fn get_savings_opportunity_percentage(&self) -> &::std::option::Option<f64> {
        &self.savings_opportunity_percentage
    }
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing..</p>
    pub fn estimated_monthly_savings(mut self, input: crate::types::EstimatedMonthlySavings) -> Self {
        self.estimated_monthly_savings = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing..</p>
    pub fn set_estimated_monthly_savings(mut self, input: ::std::option::Option<crate::types::EstimatedMonthlySavings>) -> Self {
        self.estimated_monthly_savings = input;
        self
    }
    /// <p>An object that describes the estimated monthly savings amount possible by adopting Compute Optimizer recommendations for a given resource. This is based on the On-Demand instance pricing..</p>
    pub fn get_estimated_monthly_savings(&self) -> &::std::option::Option<crate::types::EstimatedMonthlySavings> {
        &self.estimated_monthly_savings
    }
    /// Consumes the builder and constructs a [`SavingsOpportunity`](crate::types::SavingsOpportunity).
    pub fn build(self) -> crate::types::SavingsOpportunity {
        crate::types::SavingsOpportunity {
            savings_opportunity_percentage: self.savings_opportunity_percentage.unwrap_or_default(),
            estimated_monthly_savings: self.estimated_monthly_savings,
        }
    }
}
