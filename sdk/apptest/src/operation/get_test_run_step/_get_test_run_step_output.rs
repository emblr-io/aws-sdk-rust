// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTestRunStepOutput {
    /// <p>The step name of the test run step.</p>
    pub step_name: ::std::string::String,
    /// <p>The test run ID of the test run step.</p>
    pub test_run_id: ::std::string::String,
    /// <p>The test case ID of the test run step.</p>
    pub test_case_id: ::std::option::Option<::std::string::String>,
    /// <p>The test case version of the test run step.</p>
    pub test_case_version: ::std::option::Option<i32>,
    /// <p>The test suite ID of the test run step.</p>
    pub test_suite_id: ::std::option::Option<::std::string::String>,
    /// <p>The test suite version of the test run step.</p>
    pub test_suite_version: ::std::option::Option<i32>,
    /// <p>The before steps of the test run step.</p>
    pub before_step: ::std::option::Option<bool>,
    /// <p>The after steps of the test run step.</p>
    pub after_step: ::std::option::Option<bool>,
    /// <p>The status of the test run step.</p>
    pub status: crate::types::StepRunStatus,
    /// <p>The status reason of the test run step.</p>
    pub status_reason: ::std::option::Option<::std::string::String>,
    /// <p>The run start time of the test run step.</p>
    pub run_start_time: ::aws_smithy_types::DateTime,
    /// <p>The run end time of the test run step.</p>
    pub run_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The step run summary of the test run step.</p>
    pub step_run_summary: ::std::option::Option<crate::types::StepRunSummary>,
    _request_id: Option<String>,
}
impl GetTestRunStepOutput {
    /// <p>The step name of the test run step.</p>
    pub fn step_name(&self) -> &str {
        use std::ops::Deref;
        self.step_name.deref()
    }
    /// <p>The test run ID of the test run step.</p>
    pub fn test_run_id(&self) -> &str {
        use std::ops::Deref;
        self.test_run_id.deref()
    }
    /// <p>The test case ID of the test run step.</p>
    pub fn test_case_id(&self) -> ::std::option::Option<&str> {
        self.test_case_id.as_deref()
    }
    /// <p>The test case version of the test run step.</p>
    pub fn test_case_version(&self) -> ::std::option::Option<i32> {
        self.test_case_version
    }
    /// <p>The test suite ID of the test run step.</p>
    pub fn test_suite_id(&self) -> ::std::option::Option<&str> {
        self.test_suite_id.as_deref()
    }
    /// <p>The test suite version of the test run step.</p>
    pub fn test_suite_version(&self) -> ::std::option::Option<i32> {
        self.test_suite_version
    }
    /// <p>The before steps of the test run step.</p>
    pub fn before_step(&self) -> ::std::option::Option<bool> {
        self.before_step
    }
    /// <p>The after steps of the test run step.</p>
    pub fn after_step(&self) -> ::std::option::Option<bool> {
        self.after_step
    }
    /// <p>The status of the test run step.</p>
    pub fn status(&self) -> &crate::types::StepRunStatus {
        &self.status
    }
    /// <p>The status reason of the test run step.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&str> {
        self.status_reason.as_deref()
    }
    /// <p>The run start time of the test run step.</p>
    pub fn run_start_time(&self) -> &::aws_smithy_types::DateTime {
        &self.run_start_time
    }
    /// <p>The run end time of the test run step.</p>
    pub fn run_end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.run_end_time.as_ref()
    }
    /// <p>The step run summary of the test run step.</p>
    pub fn step_run_summary(&self) -> ::std::option::Option<&crate::types::StepRunSummary> {
        self.step_run_summary.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetTestRunStepOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetTestRunStepOutput {
    /// Creates a new builder-style object to manufacture [`GetTestRunStepOutput`](crate::operation::get_test_run_step::GetTestRunStepOutput).
    pub fn builder() -> crate::operation::get_test_run_step::builders::GetTestRunStepOutputBuilder {
        crate::operation::get_test_run_step::builders::GetTestRunStepOutputBuilder::default()
    }
}

/// A builder for [`GetTestRunStepOutput`](crate::operation::get_test_run_step::GetTestRunStepOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTestRunStepOutputBuilder {
    pub(crate) step_name: ::std::option::Option<::std::string::String>,
    pub(crate) test_run_id: ::std::option::Option<::std::string::String>,
    pub(crate) test_case_id: ::std::option::Option<::std::string::String>,
    pub(crate) test_case_version: ::std::option::Option<i32>,
    pub(crate) test_suite_id: ::std::option::Option<::std::string::String>,
    pub(crate) test_suite_version: ::std::option::Option<i32>,
    pub(crate) before_step: ::std::option::Option<bool>,
    pub(crate) after_step: ::std::option::Option<bool>,
    pub(crate) status: ::std::option::Option<crate::types::StepRunStatus>,
    pub(crate) status_reason: ::std::option::Option<::std::string::String>,
    pub(crate) run_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) run_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) step_run_summary: ::std::option::Option<crate::types::StepRunSummary>,
    _request_id: Option<String>,
}
impl GetTestRunStepOutputBuilder {
    /// <p>The step name of the test run step.</p>
    /// This field is required.
    pub fn step_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.step_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The step name of the test run step.</p>
    pub fn set_step_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.step_name = input;
        self
    }
    /// <p>The step name of the test run step.</p>
    pub fn get_step_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.step_name
    }
    /// <p>The test run ID of the test run step.</p>
    /// This field is required.
    pub fn test_run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test run ID of the test run step.</p>
    pub fn set_test_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_run_id = input;
        self
    }
    /// <p>The test run ID of the test run step.</p>
    pub fn get_test_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_run_id
    }
    /// <p>The test case ID of the test run step.</p>
    pub fn test_case_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_case_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test case ID of the test run step.</p>
    pub fn set_test_case_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_case_id = input;
        self
    }
    /// <p>The test case ID of the test run step.</p>
    pub fn get_test_case_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_case_id
    }
    /// <p>The test case version of the test run step.</p>
    pub fn test_case_version(mut self, input: i32) -> Self {
        self.test_case_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The test case version of the test run step.</p>
    pub fn set_test_case_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.test_case_version = input;
        self
    }
    /// <p>The test case version of the test run step.</p>
    pub fn get_test_case_version(&self) -> &::std::option::Option<i32> {
        &self.test_case_version
    }
    /// <p>The test suite ID of the test run step.</p>
    pub fn test_suite_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_suite_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test suite ID of the test run step.</p>
    pub fn set_test_suite_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_suite_id = input;
        self
    }
    /// <p>The test suite ID of the test run step.</p>
    pub fn get_test_suite_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_suite_id
    }
    /// <p>The test suite version of the test run step.</p>
    pub fn test_suite_version(mut self, input: i32) -> Self {
        self.test_suite_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The test suite version of the test run step.</p>
    pub fn set_test_suite_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.test_suite_version = input;
        self
    }
    /// <p>The test suite version of the test run step.</p>
    pub fn get_test_suite_version(&self) -> &::std::option::Option<i32> {
        &self.test_suite_version
    }
    /// <p>The before steps of the test run step.</p>
    pub fn before_step(mut self, input: bool) -> Self {
        self.before_step = ::std::option::Option::Some(input);
        self
    }
    /// <p>The before steps of the test run step.</p>
    pub fn set_before_step(mut self, input: ::std::option::Option<bool>) -> Self {
        self.before_step = input;
        self
    }
    /// <p>The before steps of the test run step.</p>
    pub fn get_before_step(&self) -> &::std::option::Option<bool> {
        &self.before_step
    }
    /// <p>The after steps of the test run step.</p>
    pub fn after_step(mut self, input: bool) -> Self {
        self.after_step = ::std::option::Option::Some(input);
        self
    }
    /// <p>The after steps of the test run step.</p>
    pub fn set_after_step(mut self, input: ::std::option::Option<bool>) -> Self {
        self.after_step = input;
        self
    }
    /// <p>The after steps of the test run step.</p>
    pub fn get_after_step(&self) -> &::std::option::Option<bool> {
        &self.after_step
    }
    /// <p>The status of the test run step.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::StepRunStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the test run step.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::StepRunStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the test run step.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::StepRunStatus> {
        &self.status
    }
    /// <p>The status reason of the test run step.</p>
    pub fn status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status reason of the test run step.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>The status reason of the test run step.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_reason
    }
    /// <p>The run start time of the test run step.</p>
    /// This field is required.
    pub fn run_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.run_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The run start time of the test run step.</p>
    pub fn set_run_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.run_start_time = input;
        self
    }
    /// <p>The run start time of the test run step.</p>
    pub fn get_run_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.run_start_time
    }
    /// <p>The run end time of the test run step.</p>
    pub fn run_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.run_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The run end time of the test run step.</p>
    pub fn set_run_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.run_end_time = input;
        self
    }
    /// <p>The run end time of the test run step.</p>
    pub fn get_run_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.run_end_time
    }
    /// <p>The step run summary of the test run step.</p>
    pub fn step_run_summary(mut self, input: crate::types::StepRunSummary) -> Self {
        self.step_run_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>The step run summary of the test run step.</p>
    pub fn set_step_run_summary(mut self, input: ::std::option::Option<crate::types::StepRunSummary>) -> Self {
        self.step_run_summary = input;
        self
    }
    /// <p>The step run summary of the test run step.</p>
    pub fn get_step_run_summary(&self) -> &::std::option::Option<crate::types::StepRunSummary> {
        &self.step_run_summary
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetTestRunStepOutput`](crate::operation::get_test_run_step::GetTestRunStepOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`step_name`](crate::operation::get_test_run_step::builders::GetTestRunStepOutputBuilder::step_name)
    /// - [`test_run_id`](crate::operation::get_test_run_step::builders::GetTestRunStepOutputBuilder::test_run_id)
    /// - [`status`](crate::operation::get_test_run_step::builders::GetTestRunStepOutputBuilder::status)
    /// - [`run_start_time`](crate::operation::get_test_run_step::builders::GetTestRunStepOutputBuilder::run_start_time)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_test_run_step::GetTestRunStepOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_test_run_step::GetTestRunStepOutput {
            step_name: self.step_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "step_name",
                    "step_name was not specified but it is required when building GetTestRunStepOutput",
                )
            })?,
            test_run_id: self.test_run_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "test_run_id",
                    "test_run_id was not specified but it is required when building GetTestRunStepOutput",
                )
            })?,
            test_case_id: self.test_case_id,
            test_case_version: self.test_case_version,
            test_suite_id: self.test_suite_id,
            test_suite_version: self.test_suite_version,
            before_step: self.before_step,
            after_step: self.after_step,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building GetTestRunStepOutput",
                )
            })?,
            status_reason: self.status_reason,
            run_start_time: self.run_start_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "run_start_time",
                    "run_start_time was not specified but it is required when building GetTestRunStepOutput",
                )
            })?,
            run_end_time: self.run_end_time,
            step_run_summary: self.step_run_summary,
            _request_id: self._request_id,
        })
    }
}
