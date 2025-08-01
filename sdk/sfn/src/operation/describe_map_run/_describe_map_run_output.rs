// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeMapRunOutput {
    /// <p>The Amazon Resource Name (ARN) that identifies a Map Run.</p>
    pub map_run_arn: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) that identifies the execution in which the Map Run was started.</p>
    pub execution_arn: ::std::string::String,
    /// <p>The current status of the Map Run.</p>
    pub status: crate::types::MapRunStatus,
    /// <p>The date when the Map Run was started.</p>
    pub start_date: ::aws_smithy_types::DateTime,
    /// <p>The date when the Map Run was stopped.</p>
    pub stop_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The maximum number of child workflow executions configured to run in parallel for the Map Run at the same time.</p>
    pub max_concurrency: i32,
    /// <p>The maximum percentage of failed child workflow executions before the Map Run fails.</p>
    pub tolerated_failure_percentage: f32,
    /// <p>The maximum number of failed child workflow executions before the Map Run fails.</p>
    pub tolerated_failure_count: i64,
    /// <p>A JSON object that contains information about the total number of items, and the item count for each processing status, such as <code>pending</code> and <code>failed</code>.</p>
    pub item_counts: ::std::option::Option<crate::types::MapRunItemCounts>,
    /// <p>A JSON object that contains information about the total number of child workflow executions for the Map Run, and the count of child workflow executions for each status, such as <code>failed</code> and <code>succeeded</code>.</p>
    pub execution_counts: ::std::option::Option<crate::types::MapRunExecutionCounts>,
    /// <p>The number of times you've redriven a Map Run. If you have not yet redriven a Map Run, the <code>redriveCount</code> is 0. This count is only updated if you successfully redrive a Map Run.</p>
    pub redrive_count: ::std::option::Option<i32>,
    /// <p>The date a Map Run was last redriven. If you have not yet redriven a Map Run, the <code>redriveDate</code> is null.</p>
    pub redrive_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeMapRunOutput {
    /// <p>The Amazon Resource Name (ARN) that identifies a Map Run.</p>
    pub fn map_run_arn(&self) -> &str {
        use std::ops::Deref;
        self.map_run_arn.deref()
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the execution in which the Map Run was started.</p>
    pub fn execution_arn(&self) -> &str {
        use std::ops::Deref;
        self.execution_arn.deref()
    }
    /// <p>The current status of the Map Run.</p>
    pub fn status(&self) -> &crate::types::MapRunStatus {
        &self.status
    }
    /// <p>The date when the Map Run was started.</p>
    pub fn start_date(&self) -> &::aws_smithy_types::DateTime {
        &self.start_date
    }
    /// <p>The date when the Map Run was stopped.</p>
    pub fn stop_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.stop_date.as_ref()
    }
    /// <p>The maximum number of child workflow executions configured to run in parallel for the Map Run at the same time.</p>
    pub fn max_concurrency(&self) -> i32 {
        self.max_concurrency
    }
    /// <p>The maximum percentage of failed child workflow executions before the Map Run fails.</p>
    pub fn tolerated_failure_percentage(&self) -> f32 {
        self.tolerated_failure_percentage
    }
    /// <p>The maximum number of failed child workflow executions before the Map Run fails.</p>
    pub fn tolerated_failure_count(&self) -> i64 {
        self.tolerated_failure_count
    }
    /// <p>A JSON object that contains information about the total number of items, and the item count for each processing status, such as <code>pending</code> and <code>failed</code>.</p>
    pub fn item_counts(&self) -> ::std::option::Option<&crate::types::MapRunItemCounts> {
        self.item_counts.as_ref()
    }
    /// <p>A JSON object that contains information about the total number of child workflow executions for the Map Run, and the count of child workflow executions for each status, such as <code>failed</code> and <code>succeeded</code>.</p>
    pub fn execution_counts(&self) -> ::std::option::Option<&crate::types::MapRunExecutionCounts> {
        self.execution_counts.as_ref()
    }
    /// <p>The number of times you've redriven a Map Run. If you have not yet redriven a Map Run, the <code>redriveCount</code> is 0. This count is only updated if you successfully redrive a Map Run.</p>
    pub fn redrive_count(&self) -> ::std::option::Option<i32> {
        self.redrive_count
    }
    /// <p>The date a Map Run was last redriven. If you have not yet redriven a Map Run, the <code>redriveDate</code> is null.</p>
    pub fn redrive_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.redrive_date.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeMapRunOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeMapRunOutput {
    /// Creates a new builder-style object to manufacture [`DescribeMapRunOutput`](crate::operation::describe_map_run::DescribeMapRunOutput).
    pub fn builder() -> crate::operation::describe_map_run::builders::DescribeMapRunOutputBuilder {
        crate::operation::describe_map_run::builders::DescribeMapRunOutputBuilder::default()
    }
}

/// A builder for [`DescribeMapRunOutput`](crate::operation::describe_map_run::DescribeMapRunOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeMapRunOutputBuilder {
    pub(crate) map_run_arn: ::std::option::Option<::std::string::String>,
    pub(crate) execution_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::MapRunStatus>,
    pub(crate) start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) stop_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) max_concurrency: ::std::option::Option<i32>,
    pub(crate) tolerated_failure_percentage: ::std::option::Option<f32>,
    pub(crate) tolerated_failure_count: ::std::option::Option<i64>,
    pub(crate) item_counts: ::std::option::Option<crate::types::MapRunItemCounts>,
    pub(crate) execution_counts: ::std::option::Option<crate::types::MapRunExecutionCounts>,
    pub(crate) redrive_count: ::std::option::Option<i32>,
    pub(crate) redrive_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeMapRunOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) that identifies a Map Run.</p>
    /// This field is required.
    pub fn map_run_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.map_run_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies a Map Run.</p>
    pub fn set_map_run_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.map_run_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies a Map Run.</p>
    pub fn get_map_run_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.map_run_arn
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the execution in which the Map Run was started.</p>
    /// This field is required.
    pub fn execution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the execution in which the Map Run was started.</p>
    pub fn set_execution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the execution in which the Map Run was started.</p>
    pub fn get_execution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_arn
    }
    /// <p>The current status of the Map Run.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::MapRunStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the Map Run.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::MapRunStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the Map Run.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::MapRunStatus> {
        &self.status
    }
    /// <p>The date when the Map Run was started.</p>
    /// This field is required.
    pub fn start_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date when the Map Run was started.</p>
    pub fn set_start_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_date = input;
        self
    }
    /// <p>The date when the Map Run was started.</p>
    pub fn get_start_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_date
    }
    /// <p>The date when the Map Run was stopped.</p>
    pub fn stop_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.stop_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date when the Map Run was stopped.</p>
    pub fn set_stop_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.stop_date = input;
        self
    }
    /// <p>The date when the Map Run was stopped.</p>
    pub fn get_stop_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.stop_date
    }
    /// <p>The maximum number of child workflow executions configured to run in parallel for the Map Run at the same time.</p>
    /// This field is required.
    pub fn max_concurrency(mut self, input: i32) -> Self {
        self.max_concurrency = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of child workflow executions configured to run in parallel for the Map Run at the same time.</p>
    pub fn set_max_concurrency(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_concurrency = input;
        self
    }
    /// <p>The maximum number of child workflow executions configured to run in parallel for the Map Run at the same time.</p>
    pub fn get_max_concurrency(&self) -> &::std::option::Option<i32> {
        &self.max_concurrency
    }
    /// <p>The maximum percentage of failed child workflow executions before the Map Run fails.</p>
    /// This field is required.
    pub fn tolerated_failure_percentage(mut self, input: f32) -> Self {
        self.tolerated_failure_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum percentage of failed child workflow executions before the Map Run fails.</p>
    pub fn set_tolerated_failure_percentage(mut self, input: ::std::option::Option<f32>) -> Self {
        self.tolerated_failure_percentage = input;
        self
    }
    /// <p>The maximum percentage of failed child workflow executions before the Map Run fails.</p>
    pub fn get_tolerated_failure_percentage(&self) -> &::std::option::Option<f32> {
        &self.tolerated_failure_percentage
    }
    /// <p>The maximum number of failed child workflow executions before the Map Run fails.</p>
    /// This field is required.
    pub fn tolerated_failure_count(mut self, input: i64) -> Self {
        self.tolerated_failure_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of failed child workflow executions before the Map Run fails.</p>
    pub fn set_tolerated_failure_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.tolerated_failure_count = input;
        self
    }
    /// <p>The maximum number of failed child workflow executions before the Map Run fails.</p>
    pub fn get_tolerated_failure_count(&self) -> &::std::option::Option<i64> {
        &self.tolerated_failure_count
    }
    /// <p>A JSON object that contains information about the total number of items, and the item count for each processing status, such as <code>pending</code> and <code>failed</code>.</p>
    /// This field is required.
    pub fn item_counts(mut self, input: crate::types::MapRunItemCounts) -> Self {
        self.item_counts = ::std::option::Option::Some(input);
        self
    }
    /// <p>A JSON object that contains information about the total number of items, and the item count for each processing status, such as <code>pending</code> and <code>failed</code>.</p>
    pub fn set_item_counts(mut self, input: ::std::option::Option<crate::types::MapRunItemCounts>) -> Self {
        self.item_counts = input;
        self
    }
    /// <p>A JSON object that contains information about the total number of items, and the item count for each processing status, such as <code>pending</code> and <code>failed</code>.</p>
    pub fn get_item_counts(&self) -> &::std::option::Option<crate::types::MapRunItemCounts> {
        &self.item_counts
    }
    /// <p>A JSON object that contains information about the total number of child workflow executions for the Map Run, and the count of child workflow executions for each status, such as <code>failed</code> and <code>succeeded</code>.</p>
    /// This field is required.
    pub fn execution_counts(mut self, input: crate::types::MapRunExecutionCounts) -> Self {
        self.execution_counts = ::std::option::Option::Some(input);
        self
    }
    /// <p>A JSON object that contains information about the total number of child workflow executions for the Map Run, and the count of child workflow executions for each status, such as <code>failed</code> and <code>succeeded</code>.</p>
    pub fn set_execution_counts(mut self, input: ::std::option::Option<crate::types::MapRunExecutionCounts>) -> Self {
        self.execution_counts = input;
        self
    }
    /// <p>A JSON object that contains information about the total number of child workflow executions for the Map Run, and the count of child workflow executions for each status, such as <code>failed</code> and <code>succeeded</code>.</p>
    pub fn get_execution_counts(&self) -> &::std::option::Option<crate::types::MapRunExecutionCounts> {
        &self.execution_counts
    }
    /// <p>The number of times you've redriven a Map Run. If you have not yet redriven a Map Run, the <code>redriveCount</code> is 0. This count is only updated if you successfully redrive a Map Run.</p>
    pub fn redrive_count(mut self, input: i32) -> Self {
        self.redrive_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of times you've redriven a Map Run. If you have not yet redriven a Map Run, the <code>redriveCount</code> is 0. This count is only updated if you successfully redrive a Map Run.</p>
    pub fn set_redrive_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.redrive_count = input;
        self
    }
    /// <p>The number of times you've redriven a Map Run. If you have not yet redriven a Map Run, the <code>redriveCount</code> is 0. This count is only updated if you successfully redrive a Map Run.</p>
    pub fn get_redrive_count(&self) -> &::std::option::Option<i32> {
        &self.redrive_count
    }
    /// <p>The date a Map Run was last redriven. If you have not yet redriven a Map Run, the <code>redriveDate</code> is null.</p>
    pub fn redrive_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.redrive_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date a Map Run was last redriven. If you have not yet redriven a Map Run, the <code>redriveDate</code> is null.</p>
    pub fn set_redrive_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.redrive_date = input;
        self
    }
    /// <p>The date a Map Run was last redriven. If you have not yet redriven a Map Run, the <code>redriveDate</code> is null.</p>
    pub fn get_redrive_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.redrive_date
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeMapRunOutput`](crate::operation::describe_map_run::DescribeMapRunOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`map_run_arn`](crate::operation::describe_map_run::builders::DescribeMapRunOutputBuilder::map_run_arn)
    /// - [`execution_arn`](crate::operation::describe_map_run::builders::DescribeMapRunOutputBuilder::execution_arn)
    /// - [`status`](crate::operation::describe_map_run::builders::DescribeMapRunOutputBuilder::status)
    /// - [`start_date`](crate::operation::describe_map_run::builders::DescribeMapRunOutputBuilder::start_date)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_map_run::DescribeMapRunOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_map_run::DescribeMapRunOutput {
            map_run_arn: self.map_run_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "map_run_arn",
                    "map_run_arn was not specified but it is required when building DescribeMapRunOutput",
                )
            })?,
            execution_arn: self.execution_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "execution_arn",
                    "execution_arn was not specified but it is required when building DescribeMapRunOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building DescribeMapRunOutput",
                )
            })?,
            start_date: self.start_date.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "start_date",
                    "start_date was not specified but it is required when building DescribeMapRunOutput",
                )
            })?,
            stop_date: self.stop_date,
            max_concurrency: self.max_concurrency.unwrap_or_default(),
            tolerated_failure_percentage: self.tolerated_failure_percentage.unwrap_or_default(),
            tolerated_failure_count: self.tolerated_failure_count.unwrap_or_default(),
            item_counts: self.item_counts,
            execution_counts: self.execution_counts,
            redrive_count: self.redrive_count,
            redrive_date: self.redrive_date,
            _request_id: self._request_id,
        })
    }
}
