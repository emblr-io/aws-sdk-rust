// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the parameters for DescribeLoadBalancerAttributes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLoadBalancerAttributesInput {
    /// <p>The name of the load balancer.</p>
    pub load_balancer_name: ::std::option::Option<::std::string::String>,
}
impl DescribeLoadBalancerAttributesInput {
    /// <p>The name of the load balancer.</p>
    pub fn load_balancer_name(&self) -> ::std::option::Option<&str> {
        self.load_balancer_name.as_deref()
    }
}
impl DescribeLoadBalancerAttributesInput {
    /// Creates a new builder-style object to manufacture [`DescribeLoadBalancerAttributesInput`](crate::operation::describe_load_balancer_attributes::DescribeLoadBalancerAttributesInput).
    pub fn builder() -> crate::operation::describe_load_balancer_attributes::builders::DescribeLoadBalancerAttributesInputBuilder {
        crate::operation::describe_load_balancer_attributes::builders::DescribeLoadBalancerAttributesInputBuilder::default()
    }
}

/// A builder for [`DescribeLoadBalancerAttributesInput`](crate::operation::describe_load_balancer_attributes::DescribeLoadBalancerAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLoadBalancerAttributesInputBuilder {
    pub(crate) load_balancer_name: ::std::option::Option<::std::string::String>,
}
impl DescribeLoadBalancerAttributesInputBuilder {
    /// <p>The name of the load balancer.</p>
    /// This field is required.
    pub fn load_balancer_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.load_balancer_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the load balancer.</p>
    pub fn set_load_balancer_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.load_balancer_name = input;
        self
    }
    /// <p>The name of the load balancer.</p>
    pub fn get_load_balancer_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.load_balancer_name
    }
    /// Consumes the builder and constructs a [`DescribeLoadBalancerAttributesInput`](crate::operation::describe_load_balancer_attributes::DescribeLoadBalancerAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_load_balancer_attributes::DescribeLoadBalancerAttributesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_load_balancer_attributes::DescribeLoadBalancerAttributesInput {
            load_balancer_name: self.load_balancer_name,
        })
    }
}
