// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAlgorithmInput {
    /// <p>The Amazon Resource Name (ARN) of the algorithm to describe.</p>
    pub algorithm_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeAlgorithmInput {
    /// <p>The Amazon Resource Name (ARN) of the algorithm to describe.</p>
    pub fn algorithm_arn(&self) -> ::std::option::Option<&str> {
        self.algorithm_arn.as_deref()
    }
}
impl DescribeAlgorithmInput {
    /// Creates a new builder-style object to manufacture [`DescribeAlgorithmInput`](crate::operation::describe_algorithm::DescribeAlgorithmInput).
    pub fn builder() -> crate::operation::describe_algorithm::builders::DescribeAlgorithmInputBuilder {
        crate::operation::describe_algorithm::builders::DescribeAlgorithmInputBuilder::default()
    }
}

/// A builder for [`DescribeAlgorithmInput`](crate::operation::describe_algorithm::DescribeAlgorithmInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAlgorithmInputBuilder {
    pub(crate) algorithm_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeAlgorithmInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the algorithm to describe.</p>
    /// This field is required.
    pub fn algorithm_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.algorithm_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the algorithm to describe.</p>
    pub fn set_algorithm_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.algorithm_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the algorithm to describe.</p>
    pub fn get_algorithm_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.algorithm_arn
    }
    /// Consumes the builder and constructs a [`DescribeAlgorithmInput`](crate::operation::describe_algorithm::DescribeAlgorithmInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_algorithm::DescribeAlgorithmInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_algorithm::DescribeAlgorithmInput {
            algorithm_arn: self.algorithm_arn,
        })
    }
}
