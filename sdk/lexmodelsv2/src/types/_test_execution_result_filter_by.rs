// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the method by which to filter the results of the test execution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TestExecutionResultFilterBy {
    /// <p>Specifies which results to filter. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/test-results-details-test-set.html">Test result details"&gt;Test results details</a> for details about different types of results.</p>
    pub result_type_filter: crate::types::TestResultTypeFilter,
    /// <p>Contains information about the method for filtering Conversation level test results.</p>
    pub conversation_level_test_results_filter_by: ::std::option::Option<crate::types::ConversationLevelTestResultsFilterBy>,
}
impl TestExecutionResultFilterBy {
    /// <p>Specifies which results to filter. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/test-results-details-test-set.html">Test result details"&gt;Test results details</a> for details about different types of results.</p>
    pub fn result_type_filter(&self) -> &crate::types::TestResultTypeFilter {
        &self.result_type_filter
    }
    /// <p>Contains information about the method for filtering Conversation level test results.</p>
    pub fn conversation_level_test_results_filter_by(&self) -> ::std::option::Option<&crate::types::ConversationLevelTestResultsFilterBy> {
        self.conversation_level_test_results_filter_by.as_ref()
    }
}
impl TestExecutionResultFilterBy {
    /// Creates a new builder-style object to manufacture [`TestExecutionResultFilterBy`](crate::types::TestExecutionResultFilterBy).
    pub fn builder() -> crate::types::builders::TestExecutionResultFilterByBuilder {
        crate::types::builders::TestExecutionResultFilterByBuilder::default()
    }
}

/// A builder for [`TestExecutionResultFilterBy`](crate::types::TestExecutionResultFilterBy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TestExecutionResultFilterByBuilder {
    pub(crate) result_type_filter: ::std::option::Option<crate::types::TestResultTypeFilter>,
    pub(crate) conversation_level_test_results_filter_by: ::std::option::Option<crate::types::ConversationLevelTestResultsFilterBy>,
}
impl TestExecutionResultFilterByBuilder {
    /// <p>Specifies which results to filter. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/test-results-details-test-set.html">Test result details"&gt;Test results details</a> for details about different types of results.</p>
    /// This field is required.
    pub fn result_type_filter(mut self, input: crate::types::TestResultTypeFilter) -> Self {
        self.result_type_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies which results to filter. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/test-results-details-test-set.html">Test result details"&gt;Test results details</a> for details about different types of results.</p>
    pub fn set_result_type_filter(mut self, input: ::std::option::Option<crate::types::TestResultTypeFilter>) -> Self {
        self.result_type_filter = input;
        self
    }
    /// <p>Specifies which results to filter. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/test-results-details-test-set.html">Test result details"&gt;Test results details</a> for details about different types of results.</p>
    pub fn get_result_type_filter(&self) -> &::std::option::Option<crate::types::TestResultTypeFilter> {
        &self.result_type_filter
    }
    /// <p>Contains information about the method for filtering Conversation level test results.</p>
    pub fn conversation_level_test_results_filter_by(mut self, input: crate::types::ConversationLevelTestResultsFilterBy) -> Self {
        self.conversation_level_test_results_filter_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the method for filtering Conversation level test results.</p>
    pub fn set_conversation_level_test_results_filter_by(
        mut self,
        input: ::std::option::Option<crate::types::ConversationLevelTestResultsFilterBy>,
    ) -> Self {
        self.conversation_level_test_results_filter_by = input;
        self
    }
    /// <p>Contains information about the method for filtering Conversation level test results.</p>
    pub fn get_conversation_level_test_results_filter_by(&self) -> &::std::option::Option<crate::types::ConversationLevelTestResultsFilterBy> {
        &self.conversation_level_test_results_filter_by
    }
    /// Consumes the builder and constructs a [`TestExecutionResultFilterBy`](crate::types::TestExecutionResultFilterBy).
    /// This method will fail if any of the following fields are not set:
    /// - [`result_type_filter`](crate::types::builders::TestExecutionResultFilterByBuilder::result_type_filter)
    pub fn build(self) -> ::std::result::Result<crate::types::TestExecutionResultFilterBy, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TestExecutionResultFilterBy {
            result_type_filter: self.result_type_filter.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "result_type_filter",
                    "result_type_filter was not specified but it is required when building TestExecutionResultFilterBy",
                )
            })?,
            conversation_level_test_results_filter_by: self.conversation_level_test_results_filter_by,
        })
    }
}
