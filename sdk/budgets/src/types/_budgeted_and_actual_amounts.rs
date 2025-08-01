// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The amount of cost or usage that you created the budget for, compared to your actual costs or usage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BudgetedAndActualAmounts {
    /// <p>The amount of cost or usage that you created the budget for.</p>
    pub budgeted_amount: ::std::option::Option<crate::types::Spend>,
    /// <p>Your actual costs or usage for a budget period.</p>
    pub actual_amount: ::std::option::Option<crate::types::Spend>,
    /// <p>The time period that's covered by this budget comparison.</p>
    pub time_period: ::std::option::Option<crate::types::TimePeriod>,
}
impl BudgetedAndActualAmounts {
    /// <p>The amount of cost or usage that you created the budget for.</p>
    pub fn budgeted_amount(&self) -> ::std::option::Option<&crate::types::Spend> {
        self.budgeted_amount.as_ref()
    }
    /// <p>Your actual costs or usage for a budget period.</p>
    pub fn actual_amount(&self) -> ::std::option::Option<&crate::types::Spend> {
        self.actual_amount.as_ref()
    }
    /// <p>The time period that's covered by this budget comparison.</p>
    pub fn time_period(&self) -> ::std::option::Option<&crate::types::TimePeriod> {
        self.time_period.as_ref()
    }
}
impl BudgetedAndActualAmounts {
    /// Creates a new builder-style object to manufacture [`BudgetedAndActualAmounts`](crate::types::BudgetedAndActualAmounts).
    pub fn builder() -> crate::types::builders::BudgetedAndActualAmountsBuilder {
        crate::types::builders::BudgetedAndActualAmountsBuilder::default()
    }
}

/// A builder for [`BudgetedAndActualAmounts`](crate::types::BudgetedAndActualAmounts).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BudgetedAndActualAmountsBuilder {
    pub(crate) budgeted_amount: ::std::option::Option<crate::types::Spend>,
    pub(crate) actual_amount: ::std::option::Option<crate::types::Spend>,
    pub(crate) time_period: ::std::option::Option<crate::types::TimePeriod>,
}
impl BudgetedAndActualAmountsBuilder {
    /// <p>The amount of cost or usage that you created the budget for.</p>
    pub fn budgeted_amount(mut self, input: crate::types::Spend) -> Self {
        self.budgeted_amount = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of cost or usage that you created the budget for.</p>
    pub fn set_budgeted_amount(mut self, input: ::std::option::Option<crate::types::Spend>) -> Self {
        self.budgeted_amount = input;
        self
    }
    /// <p>The amount of cost or usage that you created the budget for.</p>
    pub fn get_budgeted_amount(&self) -> &::std::option::Option<crate::types::Spend> {
        &self.budgeted_amount
    }
    /// <p>Your actual costs or usage for a budget period.</p>
    pub fn actual_amount(mut self, input: crate::types::Spend) -> Self {
        self.actual_amount = ::std::option::Option::Some(input);
        self
    }
    /// <p>Your actual costs or usage for a budget period.</p>
    pub fn set_actual_amount(mut self, input: ::std::option::Option<crate::types::Spend>) -> Self {
        self.actual_amount = input;
        self
    }
    /// <p>Your actual costs or usage for a budget period.</p>
    pub fn get_actual_amount(&self) -> &::std::option::Option<crate::types::Spend> {
        &self.actual_amount
    }
    /// <p>The time period that's covered by this budget comparison.</p>
    pub fn time_period(mut self, input: crate::types::TimePeriod) -> Self {
        self.time_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time period that's covered by this budget comparison.</p>
    pub fn set_time_period(mut self, input: ::std::option::Option<crate::types::TimePeriod>) -> Self {
        self.time_period = input;
        self
    }
    /// <p>The time period that's covered by this budget comparison.</p>
    pub fn get_time_period(&self) -> &::std::option::Option<crate::types::TimePeriod> {
        &self.time_period
    }
    /// Consumes the builder and constructs a [`BudgetedAndActualAmounts`](crate::types::BudgetedAndActualAmounts).
    pub fn build(self) -> crate::types::BudgetedAndActualAmounts {
        crate::types::BudgetedAndActualAmounts {
            budgeted_amount: self.budgeted_amount,
            actual_amount: self.actual_amount,
            time_period: self.time_period,
        }
    }
}
