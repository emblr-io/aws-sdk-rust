// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The period of time that's covered by a budget. The period has a start date and an end date. The start date must come before the end date. There are no restrictions on the end date.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimePeriod {
    /// <p>The start date for a budget. If you created your budget and didn't specify a start date, Amazon Web Services defaults to the start of your chosen time period (DAILY, MONTHLY, QUARTERLY, or ANNUALLY). For example, if you created your budget on January 24, 2018, chose <code>DAILY</code>, and didn't set a start date, Amazon Web Services set your start date to <code>01/24/18 00:00 UTC</code>. If you chose <code>MONTHLY</code>, Amazon Web Services set your start date to <code>01/01/18 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>You can change your start date with the <code>UpdateBudget</code> operation.</p>
    pub start: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end date for a budget. If you didn't specify an end date, Amazon Web Services set your end date to <code>06/15/87 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>After the end date, Amazon Web Services deletes the budget and all the associated notifications and subscribers. You can change your end date with the <code>UpdateBudget</code> operation.</p>
    pub end: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl TimePeriod {
    /// <p>The start date for a budget. If you created your budget and didn't specify a start date, Amazon Web Services defaults to the start of your chosen time period (DAILY, MONTHLY, QUARTERLY, or ANNUALLY). For example, if you created your budget on January 24, 2018, chose <code>DAILY</code>, and didn't set a start date, Amazon Web Services set your start date to <code>01/24/18 00:00 UTC</code>. If you chose <code>MONTHLY</code>, Amazon Web Services set your start date to <code>01/01/18 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>You can change your start date with the <code>UpdateBudget</code> operation.</p>
    pub fn start(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start.as_ref()
    }
    /// <p>The end date for a budget. If you didn't specify an end date, Amazon Web Services set your end date to <code>06/15/87 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>After the end date, Amazon Web Services deletes the budget and all the associated notifications and subscribers. You can change your end date with the <code>UpdateBudget</code> operation.</p>
    pub fn end(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end.as_ref()
    }
}
impl TimePeriod {
    /// Creates a new builder-style object to manufacture [`TimePeriod`](crate::types::TimePeriod).
    pub fn builder() -> crate::types::builders::TimePeriodBuilder {
        crate::types::builders::TimePeriodBuilder::default()
    }
}

/// A builder for [`TimePeriod`](crate::types::TimePeriod).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimePeriodBuilder {
    pub(crate) start: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl TimePeriodBuilder {
    /// <p>The start date for a budget. If you created your budget and didn't specify a start date, Amazon Web Services defaults to the start of your chosen time period (DAILY, MONTHLY, QUARTERLY, or ANNUALLY). For example, if you created your budget on January 24, 2018, chose <code>DAILY</code>, and didn't set a start date, Amazon Web Services set your start date to <code>01/24/18 00:00 UTC</code>. If you chose <code>MONTHLY</code>, Amazon Web Services set your start date to <code>01/01/18 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>You can change your start date with the <code>UpdateBudget</code> operation.</p>
    pub fn start(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start date for a budget. If you created your budget and didn't specify a start date, Amazon Web Services defaults to the start of your chosen time period (DAILY, MONTHLY, QUARTERLY, or ANNUALLY). For example, if you created your budget on January 24, 2018, chose <code>DAILY</code>, and didn't set a start date, Amazon Web Services set your start date to <code>01/24/18 00:00 UTC</code>. If you chose <code>MONTHLY</code>, Amazon Web Services set your start date to <code>01/01/18 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>You can change your start date with the <code>UpdateBudget</code> operation.</p>
    pub fn set_start(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start = input;
        self
    }
    /// <p>The start date for a budget. If you created your budget and didn't specify a start date, Amazon Web Services defaults to the start of your chosen time period (DAILY, MONTHLY, QUARTERLY, or ANNUALLY). For example, if you created your budget on January 24, 2018, chose <code>DAILY</code>, and didn't set a start date, Amazon Web Services set your start date to <code>01/24/18 00:00 UTC</code>. If you chose <code>MONTHLY</code>, Amazon Web Services set your start date to <code>01/01/18 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>You can change your start date with the <code>UpdateBudget</code> operation.</p>
    pub fn get_start(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start
    }
    /// <p>The end date for a budget. If you didn't specify an end date, Amazon Web Services set your end date to <code>06/15/87 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>After the end date, Amazon Web Services deletes the budget and all the associated notifications and subscribers. You can change your end date with the <code>UpdateBudget</code> operation.</p>
    pub fn end(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end date for a budget. If you didn't specify an end date, Amazon Web Services set your end date to <code>06/15/87 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>After the end date, Amazon Web Services deletes the budget and all the associated notifications and subscribers. You can change your end date with the <code>UpdateBudget</code> operation.</p>
    pub fn set_end(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end = input;
        self
    }
    /// <p>The end date for a budget. If you didn't specify an end date, Amazon Web Services set your end date to <code>06/15/87 00:00 UTC</code>. The defaults are the same for the Billing and Cost Management console and the API.</p>
    /// <p>After the end date, Amazon Web Services deletes the budget and all the associated notifications and subscribers. You can change your end date with the <code>UpdateBudget</code> operation.</p>
    pub fn get_end(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end
    }
    /// Consumes the builder and constructs a [`TimePeriod`](crate::types::TimePeriod).
    pub fn build(self) -> crate::types::TimePeriod {
        crate::types::TimePeriod {
            start: self.start,
            end: self.end,
        }
    }
}
