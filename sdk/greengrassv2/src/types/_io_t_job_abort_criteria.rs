// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains criteria that define when and how to cancel a job.</p>
/// <p>The deployment stops if the following conditions are true:</p>
/// <ol>
/// <li>
/// <p>The number of things that receive the deployment exceeds the <code>minNumberOfExecutedThings</code>.</p></li>
/// <li>
/// <p>The percentage of failures with type <code>failureType</code> exceeds the <code>thresholdPercentage</code>.</p></li>
/// </ol>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IoTJobAbortCriteria {
    /// <p>The type of job deployment failure that can cancel a job.</p>
    pub failure_type: crate::types::IoTJobExecutionFailureType,
    /// <p>The action to perform when the criteria are met.</p>
    pub action: crate::types::IoTJobAbortAction,
    /// <p>The minimum percentage of <code>failureType</code> failures that occur before the job can cancel.</p>
    /// <p>This parameter supports up to two digits after the decimal (for example, you can specify <code>10.9</code> or <code>10.99</code>, but not <code>10.999</code>).</p>
    pub threshold_percentage: f64,
    /// <p>The minimum number of things that receive the configuration before the job can cancel.</p>
    pub min_number_of_executed_things: i32,
}
impl IoTJobAbortCriteria {
    /// <p>The type of job deployment failure that can cancel a job.</p>
    pub fn failure_type(&self) -> &crate::types::IoTJobExecutionFailureType {
        &self.failure_type
    }
    /// <p>The action to perform when the criteria are met.</p>
    pub fn action(&self) -> &crate::types::IoTJobAbortAction {
        &self.action
    }
    /// <p>The minimum percentage of <code>failureType</code> failures that occur before the job can cancel.</p>
    /// <p>This parameter supports up to two digits after the decimal (for example, you can specify <code>10.9</code> or <code>10.99</code>, but not <code>10.999</code>).</p>
    pub fn threshold_percentage(&self) -> f64 {
        self.threshold_percentage
    }
    /// <p>The minimum number of things that receive the configuration before the job can cancel.</p>
    pub fn min_number_of_executed_things(&self) -> i32 {
        self.min_number_of_executed_things
    }
}
impl IoTJobAbortCriteria {
    /// Creates a new builder-style object to manufacture [`IoTJobAbortCriteria`](crate::types::IoTJobAbortCriteria).
    pub fn builder() -> crate::types::builders::IoTJobAbortCriteriaBuilder {
        crate::types::builders::IoTJobAbortCriteriaBuilder::default()
    }
}

/// A builder for [`IoTJobAbortCriteria`](crate::types::IoTJobAbortCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IoTJobAbortCriteriaBuilder {
    pub(crate) failure_type: ::std::option::Option<crate::types::IoTJobExecutionFailureType>,
    pub(crate) action: ::std::option::Option<crate::types::IoTJobAbortAction>,
    pub(crate) threshold_percentage: ::std::option::Option<f64>,
    pub(crate) min_number_of_executed_things: ::std::option::Option<i32>,
}
impl IoTJobAbortCriteriaBuilder {
    /// <p>The type of job deployment failure that can cancel a job.</p>
    /// This field is required.
    pub fn failure_type(mut self, input: crate::types::IoTJobExecutionFailureType) -> Self {
        self.failure_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of job deployment failure that can cancel a job.</p>
    pub fn set_failure_type(mut self, input: ::std::option::Option<crate::types::IoTJobExecutionFailureType>) -> Self {
        self.failure_type = input;
        self
    }
    /// <p>The type of job deployment failure that can cancel a job.</p>
    pub fn get_failure_type(&self) -> &::std::option::Option<crate::types::IoTJobExecutionFailureType> {
        &self.failure_type
    }
    /// <p>The action to perform when the criteria are met.</p>
    /// This field is required.
    pub fn action(mut self, input: crate::types::IoTJobAbortAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action to perform when the criteria are met.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::IoTJobAbortAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>The action to perform when the criteria are met.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::IoTJobAbortAction> {
        &self.action
    }
    /// <p>The minimum percentage of <code>failureType</code> failures that occur before the job can cancel.</p>
    /// <p>This parameter supports up to two digits after the decimal (for example, you can specify <code>10.9</code> or <code>10.99</code>, but not <code>10.999</code>).</p>
    /// This field is required.
    pub fn threshold_percentage(mut self, input: f64) -> Self {
        self.threshold_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum percentage of <code>failureType</code> failures that occur before the job can cancel.</p>
    /// <p>This parameter supports up to two digits after the decimal (for example, you can specify <code>10.9</code> or <code>10.99</code>, but not <code>10.999</code>).</p>
    pub fn set_threshold_percentage(mut self, input: ::std::option::Option<f64>) -> Self {
        self.threshold_percentage = input;
        self
    }
    /// <p>The minimum percentage of <code>failureType</code> failures that occur before the job can cancel.</p>
    /// <p>This parameter supports up to two digits after the decimal (for example, you can specify <code>10.9</code> or <code>10.99</code>, but not <code>10.999</code>).</p>
    pub fn get_threshold_percentage(&self) -> &::std::option::Option<f64> {
        &self.threshold_percentage
    }
    /// <p>The minimum number of things that receive the configuration before the job can cancel.</p>
    /// This field is required.
    pub fn min_number_of_executed_things(mut self, input: i32) -> Self {
        self.min_number_of_executed_things = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of things that receive the configuration before the job can cancel.</p>
    pub fn set_min_number_of_executed_things(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_number_of_executed_things = input;
        self
    }
    /// <p>The minimum number of things that receive the configuration before the job can cancel.</p>
    pub fn get_min_number_of_executed_things(&self) -> &::std::option::Option<i32> {
        &self.min_number_of_executed_things
    }
    /// Consumes the builder and constructs a [`IoTJobAbortCriteria`](crate::types::IoTJobAbortCriteria).
    /// This method will fail if any of the following fields are not set:
    /// - [`failure_type`](crate::types::builders::IoTJobAbortCriteriaBuilder::failure_type)
    /// - [`action`](crate::types::builders::IoTJobAbortCriteriaBuilder::action)
    /// - [`min_number_of_executed_things`](crate::types::builders::IoTJobAbortCriteriaBuilder::min_number_of_executed_things)
    pub fn build(self) -> ::std::result::Result<crate::types::IoTJobAbortCriteria, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IoTJobAbortCriteria {
            failure_type: self.failure_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "failure_type",
                    "failure_type was not specified but it is required when building IoTJobAbortCriteria",
                )
            })?,
            action: self.action.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "action",
                    "action was not specified but it is required when building IoTJobAbortCriteria",
                )
            })?,
            threshold_percentage: self.threshold_percentage.unwrap_or_default(),
            min_number_of_executed_things: self.min_number_of_executed_things.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "min_number_of_executed_things",
                    "min_number_of_executed_things was not specified but it is required when building IoTJobAbortCriteria",
                )
            })?,
        })
    }
}
