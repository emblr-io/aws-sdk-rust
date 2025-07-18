// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTestExecutionInput {
    /// <p>The execution Id of the test set execution.</p>
    pub test_execution_id: ::std::option::Option<::std::string::String>,
}
impl DescribeTestExecutionInput {
    /// <p>The execution Id of the test set execution.</p>
    pub fn test_execution_id(&self) -> ::std::option::Option<&str> {
        self.test_execution_id.as_deref()
    }
}
impl DescribeTestExecutionInput {
    /// Creates a new builder-style object to manufacture [`DescribeTestExecutionInput`](crate::operation::describe_test_execution::DescribeTestExecutionInput).
    pub fn builder() -> crate::operation::describe_test_execution::builders::DescribeTestExecutionInputBuilder {
        crate::operation::describe_test_execution::builders::DescribeTestExecutionInputBuilder::default()
    }
}

/// A builder for [`DescribeTestExecutionInput`](crate::operation::describe_test_execution::DescribeTestExecutionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTestExecutionInputBuilder {
    pub(crate) test_execution_id: ::std::option::Option<::std::string::String>,
}
impl DescribeTestExecutionInputBuilder {
    /// <p>The execution Id of the test set execution.</p>
    /// This field is required.
    pub fn test_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The execution Id of the test set execution.</p>
    pub fn set_test_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_execution_id = input;
        self
    }
    /// <p>The execution Id of the test set execution.</p>
    pub fn get_test_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_execution_id
    }
    /// Consumes the builder and constructs a [`DescribeTestExecutionInput`](crate::operation::describe_test_execution::DescribeTestExecutionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_test_execution::DescribeTestExecutionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_test_execution::DescribeTestExecutionInput {
            test_execution_id: self.test_execution_id,
        })
    }
}
