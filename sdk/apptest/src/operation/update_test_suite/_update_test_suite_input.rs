// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTestSuiteInput {
    /// <p>The test suite ID of the test suite.</p>
    pub test_suite_id: ::std::option::Option<::std::string::String>,
    /// <p>The description of the test suite.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The before steps for the test suite.</p>
    pub before_steps: ::std::option::Option<::std::vec::Vec<crate::types::Step>>,
    /// <p>The after steps of the test suite.</p>
    pub after_steps: ::std::option::Option<::std::vec::Vec<crate::types::Step>>,
    /// <p>The test cases in the test suite.</p>
    pub test_cases: ::std::option::Option<crate::types::TestCases>,
}
impl UpdateTestSuiteInput {
    /// <p>The test suite ID of the test suite.</p>
    pub fn test_suite_id(&self) -> ::std::option::Option<&str> {
        self.test_suite_id.as_deref()
    }
    /// <p>The description of the test suite.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The before steps for the test suite.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.before_steps.is_none()`.
    pub fn before_steps(&self) -> &[crate::types::Step] {
        self.before_steps.as_deref().unwrap_or_default()
    }
    /// <p>The after steps of the test suite.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.after_steps.is_none()`.
    pub fn after_steps(&self) -> &[crate::types::Step] {
        self.after_steps.as_deref().unwrap_or_default()
    }
    /// <p>The test cases in the test suite.</p>
    pub fn test_cases(&self) -> ::std::option::Option<&crate::types::TestCases> {
        self.test_cases.as_ref()
    }
}
impl UpdateTestSuiteInput {
    /// Creates a new builder-style object to manufacture [`UpdateTestSuiteInput`](crate::operation::update_test_suite::UpdateTestSuiteInput).
    pub fn builder() -> crate::operation::update_test_suite::builders::UpdateTestSuiteInputBuilder {
        crate::operation::update_test_suite::builders::UpdateTestSuiteInputBuilder::default()
    }
}

/// A builder for [`UpdateTestSuiteInput`](crate::operation::update_test_suite::UpdateTestSuiteInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTestSuiteInputBuilder {
    pub(crate) test_suite_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) before_steps: ::std::option::Option<::std::vec::Vec<crate::types::Step>>,
    pub(crate) after_steps: ::std::option::Option<::std::vec::Vec<crate::types::Step>>,
    pub(crate) test_cases: ::std::option::Option<crate::types::TestCases>,
}
impl UpdateTestSuiteInputBuilder {
    /// <p>The test suite ID of the test suite.</p>
    /// This field is required.
    pub fn test_suite_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_suite_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test suite ID of the test suite.</p>
    pub fn set_test_suite_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_suite_id = input;
        self
    }
    /// <p>The test suite ID of the test suite.</p>
    pub fn get_test_suite_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_suite_id
    }
    /// <p>The description of the test suite.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the test suite.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the test suite.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `before_steps`.
    ///
    /// To override the contents of this collection use [`set_before_steps`](Self::set_before_steps).
    ///
    /// <p>The before steps for the test suite.</p>
    pub fn before_steps(mut self, input: crate::types::Step) -> Self {
        let mut v = self.before_steps.unwrap_or_default();
        v.push(input);
        self.before_steps = ::std::option::Option::Some(v);
        self
    }
    /// <p>The before steps for the test suite.</p>
    pub fn set_before_steps(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Step>>) -> Self {
        self.before_steps = input;
        self
    }
    /// <p>The before steps for the test suite.</p>
    pub fn get_before_steps(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Step>> {
        &self.before_steps
    }
    /// Appends an item to `after_steps`.
    ///
    /// To override the contents of this collection use [`set_after_steps`](Self::set_after_steps).
    ///
    /// <p>The after steps of the test suite.</p>
    pub fn after_steps(mut self, input: crate::types::Step) -> Self {
        let mut v = self.after_steps.unwrap_or_default();
        v.push(input);
        self.after_steps = ::std::option::Option::Some(v);
        self
    }
    /// <p>The after steps of the test suite.</p>
    pub fn set_after_steps(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Step>>) -> Self {
        self.after_steps = input;
        self
    }
    /// <p>The after steps of the test suite.</p>
    pub fn get_after_steps(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Step>> {
        &self.after_steps
    }
    /// <p>The test cases in the test suite.</p>
    pub fn test_cases(mut self, input: crate::types::TestCases) -> Self {
        self.test_cases = ::std::option::Option::Some(input);
        self
    }
    /// <p>The test cases in the test suite.</p>
    pub fn set_test_cases(mut self, input: ::std::option::Option<crate::types::TestCases>) -> Self {
        self.test_cases = input;
        self
    }
    /// <p>The test cases in the test suite.</p>
    pub fn get_test_cases(&self) -> &::std::option::Option<crate::types::TestCases> {
        &self.test_cases
    }
    /// Consumes the builder and constructs a [`UpdateTestSuiteInput`](crate::operation::update_test_suite::UpdateTestSuiteInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_test_suite::UpdateTestSuiteInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_test_suite::UpdateTestSuiteInput {
            test_suite_id: self.test_suite_id,
            description: self.description,
            before_steps: self.before_steps,
            after_steps: self.after_steps,
            test_cases: self.test_cases,
        })
    }
}
