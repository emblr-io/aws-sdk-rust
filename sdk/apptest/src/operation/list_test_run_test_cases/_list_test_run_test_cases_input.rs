// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTestRunTestCasesInput {
    /// <p>The test run ID of the test cases.</p>
    pub test_run_id: ::std::option::Option<::std::string::String>,
    /// <p>The token from a previous request to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of test run test cases to return in one page of results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListTestRunTestCasesInput {
    /// <p>The test run ID of the test cases.</p>
    pub fn test_run_id(&self) -> ::std::option::Option<&str> {
        self.test_run_id.as_deref()
    }
    /// <p>The token from a previous request to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of test run test cases to return in one page of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListTestRunTestCasesInput {
    /// Creates a new builder-style object to manufacture [`ListTestRunTestCasesInput`](crate::operation::list_test_run_test_cases::ListTestRunTestCasesInput).
    pub fn builder() -> crate::operation::list_test_run_test_cases::builders::ListTestRunTestCasesInputBuilder {
        crate::operation::list_test_run_test_cases::builders::ListTestRunTestCasesInputBuilder::default()
    }
}

/// A builder for [`ListTestRunTestCasesInput`](crate::operation::list_test_run_test_cases::ListTestRunTestCasesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTestRunTestCasesInputBuilder {
    pub(crate) test_run_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListTestRunTestCasesInputBuilder {
    /// <p>The test run ID of the test cases.</p>
    /// This field is required.
    pub fn test_run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test run ID of the test cases.</p>
    pub fn set_test_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_run_id = input;
        self
    }
    /// <p>The test run ID of the test cases.</p>
    pub fn get_test_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_run_id
    }
    /// <p>The token from a previous request to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token from a previous request to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token from a previous request to retrieve the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of test run test cases to return in one page of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of test run test cases to return in one page of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of test run test cases to return in one page of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListTestRunTestCasesInput`](crate::operation::list_test_run_test_cases::ListTestRunTestCasesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_test_run_test_cases::ListTestRunTestCasesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_test_run_test_cases::ListTestRunTestCasesInput {
            test_run_id: self.test_run_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
