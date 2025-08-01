// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeRoutingControlInput {
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    pub routing_control_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeRoutingControlInput {
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    pub fn routing_control_arn(&self) -> ::std::option::Option<&str> {
        self.routing_control_arn.as_deref()
    }
}
impl DescribeRoutingControlInput {
    /// Creates a new builder-style object to manufacture [`DescribeRoutingControlInput`](crate::operation::describe_routing_control::DescribeRoutingControlInput).
    pub fn builder() -> crate::operation::describe_routing_control::builders::DescribeRoutingControlInputBuilder {
        crate::operation::describe_routing_control::builders::DescribeRoutingControlInputBuilder::default()
    }
}

/// A builder for [`DescribeRoutingControlInput`](crate::operation::describe_routing_control::DescribeRoutingControlInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeRoutingControlInputBuilder {
    pub(crate) routing_control_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeRoutingControlInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    /// This field is required.
    pub fn routing_control_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.routing_control_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    pub fn set_routing_control_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.routing_control_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    pub fn get_routing_control_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.routing_control_arn
    }
    /// Consumes the builder and constructs a [`DescribeRoutingControlInput`](crate::operation::describe_routing_control::DescribeRoutingControlInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_routing_control::DescribeRoutingControlInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_routing_control::DescribeRoutingControlInput {
            routing_control_arn: self.routing_control_arn,
        })
    }
}
