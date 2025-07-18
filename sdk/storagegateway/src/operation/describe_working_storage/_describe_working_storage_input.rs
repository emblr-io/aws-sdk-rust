// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A JSON object containing the Amazon Resource Name (ARN) of the gateway.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeWorkingStorageInput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub gateway_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeWorkingStorageInput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn gateway_arn(&self) -> ::std::option::Option<&str> {
        self.gateway_arn.as_deref()
    }
}
impl DescribeWorkingStorageInput {
    /// Creates a new builder-style object to manufacture [`DescribeWorkingStorageInput`](crate::operation::describe_working_storage::DescribeWorkingStorageInput).
    pub fn builder() -> crate::operation::describe_working_storage::builders::DescribeWorkingStorageInputBuilder {
        crate::operation::describe_working_storage::builders::DescribeWorkingStorageInputBuilder::default()
    }
}

/// A builder for [`DescribeWorkingStorageInput`](crate::operation::describe_working_storage::DescribeWorkingStorageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeWorkingStorageInputBuilder {
    pub(crate) gateway_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeWorkingStorageInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    /// This field is required.
    pub fn gateway_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn set_gateway_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn get_gateway_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_arn
    }
    /// Consumes the builder and constructs a [`DescribeWorkingStorageInput`](crate::operation::describe_working_storage::DescribeWorkingStorageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_working_storage::DescribeWorkingStorageInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_working_storage::DescribeWorkingStorageInput {
            gateway_arn: self.gateway_arn,
        })
    }
}
