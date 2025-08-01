// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeHubInput {
    /// <p>The ARN of the Hub resource to retrieve.</p>
    pub hub_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeHubInput {
    /// <p>The ARN of the Hub resource to retrieve.</p>
    pub fn hub_arn(&self) -> ::std::option::Option<&str> {
        self.hub_arn.as_deref()
    }
}
impl DescribeHubInput {
    /// Creates a new builder-style object to manufacture [`DescribeHubInput`](crate::operation::describe_hub::DescribeHubInput).
    pub fn builder() -> crate::operation::describe_hub::builders::DescribeHubInputBuilder {
        crate::operation::describe_hub::builders::DescribeHubInputBuilder::default()
    }
}

/// A builder for [`DescribeHubInput`](crate::operation::describe_hub::DescribeHubInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeHubInputBuilder {
    pub(crate) hub_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeHubInputBuilder {
    /// <p>The ARN of the Hub resource to retrieve.</p>
    pub fn hub_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Hub resource to retrieve.</p>
    pub fn set_hub_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_arn = input;
        self
    }
    /// <p>The ARN of the Hub resource to retrieve.</p>
    pub fn get_hub_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_arn
    }
    /// Consumes the builder and constructs a [`DescribeHubInput`](crate::operation::describe_hub::DescribeHubInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::describe_hub::DescribeHubInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_hub::DescribeHubInput { hub_arn: self.hub_arn })
    }
}
