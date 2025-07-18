// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSuiteRunOutput {
    /// <p>Suite definition ID for the test suite run.</p>
    pub suite_definition_id: ::std::option::Option<::std::string::String>,
    /// <p>Suite definition version for the test suite run.</p>
    pub suite_definition_version: ::std::option::Option<::std::string::String>,
    /// <p>Suite run ID for the test suite run.</p>
    pub suite_run_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the suite run.</p>
    pub suite_run_arn: ::std::option::Option<::std::string::String>,
    /// <p>Suite run configuration for the test suite run.</p>
    pub suite_run_configuration: ::std::option::Option<crate::types::SuiteRunConfiguration>,
    /// <p>Test results for the test suite run.</p>
    pub test_result: ::std::option::Option<crate::types::TestResult>,
    /// <p>Date (in Unix epoch time) when the test suite run started.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Date (in Unix epoch time) when the test suite run ended.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Status for the test suite run.</p>
    pub status: ::std::option::Option<crate::types::SuiteRunStatus>,
    /// <p>Error reason for any test suite run failure.</p>
    pub error_reason: ::std::option::Option<::std::string::String>,
    /// <p>The tags attached to the suite run.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetSuiteRunOutput {
    /// <p>Suite definition ID for the test suite run.</p>
    pub fn suite_definition_id(&self) -> ::std::option::Option<&str> {
        self.suite_definition_id.as_deref()
    }
    /// <p>Suite definition version for the test suite run.</p>
    pub fn suite_definition_version(&self) -> ::std::option::Option<&str> {
        self.suite_definition_version.as_deref()
    }
    /// <p>Suite run ID for the test suite run.</p>
    pub fn suite_run_id(&self) -> ::std::option::Option<&str> {
        self.suite_run_id.as_deref()
    }
    /// <p>The ARN of the suite run.</p>
    pub fn suite_run_arn(&self) -> ::std::option::Option<&str> {
        self.suite_run_arn.as_deref()
    }
    /// <p>Suite run configuration for the test suite run.</p>
    pub fn suite_run_configuration(&self) -> ::std::option::Option<&crate::types::SuiteRunConfiguration> {
        self.suite_run_configuration.as_ref()
    }
    /// <p>Test results for the test suite run.</p>
    pub fn test_result(&self) -> ::std::option::Option<&crate::types::TestResult> {
        self.test_result.as_ref()
    }
    /// <p>Date (in Unix epoch time) when the test suite run started.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>Date (in Unix epoch time) when the test suite run ended.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>Status for the test suite run.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SuiteRunStatus> {
        self.status.as_ref()
    }
    /// <p>Error reason for any test suite run failure.</p>
    pub fn error_reason(&self) -> ::std::option::Option<&str> {
        self.error_reason.as_deref()
    }
    /// <p>The tags attached to the suite run.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetSuiteRunOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSuiteRunOutput {
    /// Creates a new builder-style object to manufacture [`GetSuiteRunOutput`](crate::operation::get_suite_run::GetSuiteRunOutput).
    pub fn builder() -> crate::operation::get_suite_run::builders::GetSuiteRunOutputBuilder {
        crate::operation::get_suite_run::builders::GetSuiteRunOutputBuilder::default()
    }
}

/// A builder for [`GetSuiteRunOutput`](crate::operation::get_suite_run::GetSuiteRunOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSuiteRunOutputBuilder {
    pub(crate) suite_definition_id: ::std::option::Option<::std::string::String>,
    pub(crate) suite_definition_version: ::std::option::Option<::std::string::String>,
    pub(crate) suite_run_id: ::std::option::Option<::std::string::String>,
    pub(crate) suite_run_arn: ::std::option::Option<::std::string::String>,
    pub(crate) suite_run_configuration: ::std::option::Option<crate::types::SuiteRunConfiguration>,
    pub(crate) test_result: ::std::option::Option<crate::types::TestResult>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::SuiteRunStatus>,
    pub(crate) error_reason: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetSuiteRunOutputBuilder {
    /// <p>Suite definition ID for the test suite run.</p>
    pub fn suite_definition_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.suite_definition_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Suite definition ID for the test suite run.</p>
    pub fn set_suite_definition_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.suite_definition_id = input;
        self
    }
    /// <p>Suite definition ID for the test suite run.</p>
    pub fn get_suite_definition_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.suite_definition_id
    }
    /// <p>Suite definition version for the test suite run.</p>
    pub fn suite_definition_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.suite_definition_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Suite definition version for the test suite run.</p>
    pub fn set_suite_definition_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.suite_definition_version = input;
        self
    }
    /// <p>Suite definition version for the test suite run.</p>
    pub fn get_suite_definition_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.suite_definition_version
    }
    /// <p>Suite run ID for the test suite run.</p>
    pub fn suite_run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.suite_run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Suite run ID for the test suite run.</p>
    pub fn set_suite_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.suite_run_id = input;
        self
    }
    /// <p>Suite run ID for the test suite run.</p>
    pub fn get_suite_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.suite_run_id
    }
    /// <p>The ARN of the suite run.</p>
    pub fn suite_run_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.suite_run_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the suite run.</p>
    pub fn set_suite_run_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.suite_run_arn = input;
        self
    }
    /// <p>The ARN of the suite run.</p>
    pub fn get_suite_run_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.suite_run_arn
    }
    /// <p>Suite run configuration for the test suite run.</p>
    pub fn suite_run_configuration(mut self, input: crate::types::SuiteRunConfiguration) -> Self {
        self.suite_run_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Suite run configuration for the test suite run.</p>
    pub fn set_suite_run_configuration(mut self, input: ::std::option::Option<crate::types::SuiteRunConfiguration>) -> Self {
        self.suite_run_configuration = input;
        self
    }
    /// <p>Suite run configuration for the test suite run.</p>
    pub fn get_suite_run_configuration(&self) -> &::std::option::Option<crate::types::SuiteRunConfiguration> {
        &self.suite_run_configuration
    }
    /// <p>Test results for the test suite run.</p>
    pub fn test_result(mut self, input: crate::types::TestResult) -> Self {
        self.test_result = ::std::option::Option::Some(input);
        self
    }
    /// <p>Test results for the test suite run.</p>
    pub fn set_test_result(mut self, input: ::std::option::Option<crate::types::TestResult>) -> Self {
        self.test_result = input;
        self
    }
    /// <p>Test results for the test suite run.</p>
    pub fn get_test_result(&self) -> &::std::option::Option<crate::types::TestResult> {
        &self.test_result
    }
    /// <p>Date (in Unix epoch time) when the test suite run started.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Date (in Unix epoch time) when the test suite run started.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>Date (in Unix epoch time) when the test suite run started.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>Date (in Unix epoch time) when the test suite run ended.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Date (in Unix epoch time) when the test suite run ended.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>Date (in Unix epoch time) when the test suite run ended.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>Status for the test suite run.</p>
    pub fn status(mut self, input: crate::types::SuiteRunStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status for the test suite run.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SuiteRunStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Status for the test suite run.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SuiteRunStatus> {
        &self.status
    }
    /// <p>Error reason for any test suite run failure.</p>
    pub fn error_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Error reason for any test suite run failure.</p>
    pub fn set_error_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_reason = input;
        self
    }
    /// <p>Error reason for any test suite run failure.</p>
    pub fn get_error_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_reason
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags attached to the suite run.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags attached to the suite run.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags attached to the suite run.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSuiteRunOutput`](crate::operation::get_suite_run::GetSuiteRunOutput).
    pub fn build(self) -> crate::operation::get_suite_run::GetSuiteRunOutput {
        crate::operation::get_suite_run::GetSuiteRunOutput {
            suite_definition_id: self.suite_definition_id,
            suite_definition_version: self.suite_definition_version,
            suite_run_id: self.suite_run_id,
            suite_run_arn: self.suite_run_arn,
            suite_run_configuration: self.suite_run_configuration,
            test_result: self.test_result,
            start_time: self.start_time,
            end_time: self.end_time,
            status: self.status,
            error_reason: self.error_reason,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
