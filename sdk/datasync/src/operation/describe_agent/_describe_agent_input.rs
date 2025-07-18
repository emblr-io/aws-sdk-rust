// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>DescribeAgent</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAgentInput {
    /// <p>Specifies the Amazon Resource Name (ARN) of the DataSync agent that you want information about.</p>
    pub agent_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeAgentInput {
    /// <p>Specifies the Amazon Resource Name (ARN) of the DataSync agent that you want information about.</p>
    pub fn agent_arn(&self) -> ::std::option::Option<&str> {
        self.agent_arn.as_deref()
    }
}
impl DescribeAgentInput {
    /// Creates a new builder-style object to manufacture [`DescribeAgentInput`](crate::operation::describe_agent::DescribeAgentInput).
    pub fn builder() -> crate::operation::describe_agent::builders::DescribeAgentInputBuilder {
        crate::operation::describe_agent::builders::DescribeAgentInputBuilder::default()
    }
}

/// A builder for [`DescribeAgentInput`](crate::operation::describe_agent::DescribeAgentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAgentInputBuilder {
    pub(crate) agent_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeAgentInputBuilder {
    /// <p>Specifies the Amazon Resource Name (ARN) of the DataSync agent that you want information about.</p>
    /// This field is required.
    pub fn agent_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the DataSync agent that you want information about.</p>
    pub fn set_agent_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_arn = input;
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the DataSync agent that you want information about.</p>
    pub fn get_agent_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_arn
    }
    /// Consumes the builder and constructs a [`DescribeAgentInput`](crate::operation::describe_agent::DescribeAgentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_agent::DescribeAgentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_agent::DescribeAgentInput { agent_arn: self.agent_arn })
    }
}
