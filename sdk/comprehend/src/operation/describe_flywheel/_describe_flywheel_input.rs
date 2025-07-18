// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFlywheelInput {
    /// <p>The Amazon Resource Number (ARN) of the flywheel.</p>
    pub flywheel_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeFlywheelInput {
    /// <p>The Amazon Resource Number (ARN) of the flywheel.</p>
    pub fn flywheel_arn(&self) -> ::std::option::Option<&str> {
        self.flywheel_arn.as_deref()
    }
}
impl DescribeFlywheelInput {
    /// Creates a new builder-style object to manufacture [`DescribeFlywheelInput`](crate::operation::describe_flywheel::DescribeFlywheelInput).
    pub fn builder() -> crate::operation::describe_flywheel::builders::DescribeFlywheelInputBuilder {
        crate::operation::describe_flywheel::builders::DescribeFlywheelInputBuilder::default()
    }
}

/// A builder for [`DescribeFlywheelInput`](crate::operation::describe_flywheel::DescribeFlywheelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFlywheelInputBuilder {
    pub(crate) flywheel_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeFlywheelInputBuilder {
    /// <p>The Amazon Resource Number (ARN) of the flywheel.</p>
    /// This field is required.
    pub fn flywheel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flywheel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the flywheel.</p>
    pub fn set_flywheel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flywheel_arn = input;
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the flywheel.</p>
    pub fn get_flywheel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.flywheel_arn
    }
    /// Consumes the builder and constructs a [`DescribeFlywheelInput`](crate::operation::describe_flywheel::DescribeFlywheelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_flywheel::DescribeFlywheelInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_flywheel::DescribeFlywheelInput {
            flywheel_arn: self.flywheel_arn,
        })
    }
}
