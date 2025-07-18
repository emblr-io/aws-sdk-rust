// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTestExecutionOutput {
    /// <p>The execution Id for the test set execution.</p>
    pub test_execution_id: ::std::option::Option<::std::string::String>,
    /// <p>The execution creation date and time for the test set execution.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time of the last update for the execution.</p>
    pub last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The test execution status for the test execution.</p>
    pub test_execution_status: ::std::option::Option<crate::types::TestExecutionStatus>,
    /// <p>The test set Id for the test set execution.</p>
    pub test_set_id: ::std::option::Option<::std::string::String>,
    /// <p>The test set name of the test set execution.</p>
    pub test_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The target bot for the test set execution details.</p>
    pub target: ::std::option::Option<crate::types::TestExecutionTarget>,
    /// <p>Indicates whether we use streaming or non-streaming APIs are used for the test set execution. For streaming, <code>StartConversation</code> Amazon Lex Runtime API is used. Whereas for non-streaming, <code>RecognizeUtterance</code> and <code>RecognizeText</code> Amazon Lex Runtime API is used.</p>
    pub api_mode: ::std::option::Option<crate::types::TestExecutionApiMode>,
    /// <p>Indicates whether test set is audio or text.</p>
    pub test_execution_modality: ::std::option::Option<crate::types::TestExecutionModality>,
    /// <p>Reasons for the failure of the test set execution.</p>
    pub failure_reasons: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl DescribeTestExecutionOutput {
    /// <p>The execution Id for the test set execution.</p>
    pub fn test_execution_id(&self) -> ::std::option::Option<&str> {
        self.test_execution_id.as_deref()
    }
    /// <p>The execution creation date and time for the test set execution.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
    /// <p>The date and time of the last update for the execution.</p>
    pub fn last_updated_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_date_time.as_ref()
    }
    /// <p>The test execution status for the test execution.</p>
    pub fn test_execution_status(&self) -> ::std::option::Option<&crate::types::TestExecutionStatus> {
        self.test_execution_status.as_ref()
    }
    /// <p>The test set Id for the test set execution.</p>
    pub fn test_set_id(&self) -> ::std::option::Option<&str> {
        self.test_set_id.as_deref()
    }
    /// <p>The test set name of the test set execution.</p>
    pub fn test_set_name(&self) -> ::std::option::Option<&str> {
        self.test_set_name.as_deref()
    }
    /// <p>The target bot for the test set execution details.</p>
    pub fn target(&self) -> ::std::option::Option<&crate::types::TestExecutionTarget> {
        self.target.as_ref()
    }
    /// <p>Indicates whether we use streaming or non-streaming APIs are used for the test set execution. For streaming, <code>StartConversation</code> Amazon Lex Runtime API is used. Whereas for non-streaming, <code>RecognizeUtterance</code> and <code>RecognizeText</code> Amazon Lex Runtime API is used.</p>
    pub fn api_mode(&self) -> ::std::option::Option<&crate::types::TestExecutionApiMode> {
        self.api_mode.as_ref()
    }
    /// <p>Indicates whether test set is audio or text.</p>
    pub fn test_execution_modality(&self) -> ::std::option::Option<&crate::types::TestExecutionModality> {
        self.test_execution_modality.as_ref()
    }
    /// <p>Reasons for the failure of the test set execution.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failure_reasons.is_none()`.
    pub fn failure_reasons(&self) -> &[::std::string::String] {
        self.failure_reasons.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeTestExecutionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeTestExecutionOutput {
    /// Creates a new builder-style object to manufacture [`DescribeTestExecutionOutput`](crate::operation::describe_test_execution::DescribeTestExecutionOutput).
    pub fn builder() -> crate::operation::describe_test_execution::builders::DescribeTestExecutionOutputBuilder {
        crate::operation::describe_test_execution::builders::DescribeTestExecutionOutputBuilder::default()
    }
}

/// A builder for [`DescribeTestExecutionOutput`](crate::operation::describe_test_execution::DescribeTestExecutionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTestExecutionOutputBuilder {
    pub(crate) test_execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) test_execution_status: ::std::option::Option<crate::types::TestExecutionStatus>,
    pub(crate) test_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) test_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) target: ::std::option::Option<crate::types::TestExecutionTarget>,
    pub(crate) api_mode: ::std::option::Option<crate::types::TestExecutionApiMode>,
    pub(crate) test_execution_modality: ::std::option::Option<crate::types::TestExecutionModality>,
    pub(crate) failure_reasons: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl DescribeTestExecutionOutputBuilder {
    /// <p>The execution Id for the test set execution.</p>
    pub fn test_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The execution Id for the test set execution.</p>
    pub fn set_test_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_execution_id = input;
        self
    }
    /// <p>The execution Id for the test set execution.</p>
    pub fn get_test_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_execution_id
    }
    /// <p>The execution creation date and time for the test set execution.</p>
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The execution creation date and time for the test set execution.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The execution creation date and time for the test set execution.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    /// <p>The date and time of the last update for the execution.</p>
    pub fn last_updated_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time of the last update for the execution.</p>
    pub fn set_last_updated_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_date_time = input;
        self
    }
    /// <p>The date and time of the last update for the execution.</p>
    pub fn get_last_updated_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_date_time
    }
    /// <p>The test execution status for the test execution.</p>
    pub fn test_execution_status(mut self, input: crate::types::TestExecutionStatus) -> Self {
        self.test_execution_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The test execution status for the test execution.</p>
    pub fn set_test_execution_status(mut self, input: ::std::option::Option<crate::types::TestExecutionStatus>) -> Self {
        self.test_execution_status = input;
        self
    }
    /// <p>The test execution status for the test execution.</p>
    pub fn get_test_execution_status(&self) -> &::std::option::Option<crate::types::TestExecutionStatus> {
        &self.test_execution_status
    }
    /// <p>The test set Id for the test set execution.</p>
    pub fn test_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test set Id for the test set execution.</p>
    pub fn set_test_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_set_id = input;
        self
    }
    /// <p>The test set Id for the test set execution.</p>
    pub fn get_test_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_set_id
    }
    /// <p>The test set name of the test set execution.</p>
    pub fn test_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test set name of the test set execution.</p>
    pub fn set_test_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_set_name = input;
        self
    }
    /// <p>The test set name of the test set execution.</p>
    pub fn get_test_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_set_name
    }
    /// <p>The target bot for the test set execution details.</p>
    pub fn target(mut self, input: crate::types::TestExecutionTarget) -> Self {
        self.target = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target bot for the test set execution details.</p>
    pub fn set_target(mut self, input: ::std::option::Option<crate::types::TestExecutionTarget>) -> Self {
        self.target = input;
        self
    }
    /// <p>The target bot for the test set execution details.</p>
    pub fn get_target(&self) -> &::std::option::Option<crate::types::TestExecutionTarget> {
        &self.target
    }
    /// <p>Indicates whether we use streaming or non-streaming APIs are used for the test set execution. For streaming, <code>StartConversation</code> Amazon Lex Runtime API is used. Whereas for non-streaming, <code>RecognizeUtterance</code> and <code>RecognizeText</code> Amazon Lex Runtime API is used.</p>
    pub fn api_mode(mut self, input: crate::types::TestExecutionApiMode) -> Self {
        self.api_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether we use streaming or non-streaming APIs are used for the test set execution. For streaming, <code>StartConversation</code> Amazon Lex Runtime API is used. Whereas for non-streaming, <code>RecognizeUtterance</code> and <code>RecognizeText</code> Amazon Lex Runtime API is used.</p>
    pub fn set_api_mode(mut self, input: ::std::option::Option<crate::types::TestExecutionApiMode>) -> Self {
        self.api_mode = input;
        self
    }
    /// <p>Indicates whether we use streaming or non-streaming APIs are used for the test set execution. For streaming, <code>StartConversation</code> Amazon Lex Runtime API is used. Whereas for non-streaming, <code>RecognizeUtterance</code> and <code>RecognizeText</code> Amazon Lex Runtime API is used.</p>
    pub fn get_api_mode(&self) -> &::std::option::Option<crate::types::TestExecutionApiMode> {
        &self.api_mode
    }
    /// <p>Indicates whether test set is audio or text.</p>
    pub fn test_execution_modality(mut self, input: crate::types::TestExecutionModality) -> Self {
        self.test_execution_modality = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether test set is audio or text.</p>
    pub fn set_test_execution_modality(mut self, input: ::std::option::Option<crate::types::TestExecutionModality>) -> Self {
        self.test_execution_modality = input;
        self
    }
    /// <p>Indicates whether test set is audio or text.</p>
    pub fn get_test_execution_modality(&self) -> &::std::option::Option<crate::types::TestExecutionModality> {
        &self.test_execution_modality
    }
    /// Appends an item to `failure_reasons`.
    ///
    /// To override the contents of this collection use [`set_failure_reasons`](Self::set_failure_reasons).
    ///
    /// <p>Reasons for the failure of the test set execution.</p>
    pub fn failure_reasons(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.failure_reasons.unwrap_or_default();
        v.push(input.into());
        self.failure_reasons = ::std::option::Option::Some(v);
        self
    }
    /// <p>Reasons for the failure of the test set execution.</p>
    pub fn set_failure_reasons(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.failure_reasons = input;
        self
    }
    /// <p>Reasons for the failure of the test set execution.</p>
    pub fn get_failure_reasons(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.failure_reasons
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeTestExecutionOutput`](crate::operation::describe_test_execution::DescribeTestExecutionOutput).
    pub fn build(self) -> crate::operation::describe_test_execution::DescribeTestExecutionOutput {
        crate::operation::describe_test_execution::DescribeTestExecutionOutput {
            test_execution_id: self.test_execution_id,
            creation_date_time: self.creation_date_time,
            last_updated_date_time: self.last_updated_date_time,
            test_execution_status: self.test_execution_status,
            test_set_id: self.test_set_id,
            test_set_name: self.test_set_name,
            target: self.target,
            api_mode: self.api_mode,
            test_execution_modality: self.test_execution_modality,
            failure_reasons: self.failure_reasons,
            _request_id: self._request_id,
        }
    }
}
