// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConnectorOperationInput {
    /// <p>ARN of the connector operation to be described.</p>
    pub connector_operation_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeConnectorOperationInput {
    /// <p>ARN of the connector operation to be described.</p>
    pub fn connector_operation_arn(&self) -> ::std::option::Option<&str> {
        self.connector_operation_arn.as_deref()
    }
}
impl DescribeConnectorOperationInput {
    /// Creates a new builder-style object to manufacture [`DescribeConnectorOperationInput`](crate::operation::describe_connector_operation::DescribeConnectorOperationInput).
    pub fn builder() -> crate::operation::describe_connector_operation::builders::DescribeConnectorOperationInputBuilder {
        crate::operation::describe_connector_operation::builders::DescribeConnectorOperationInputBuilder::default()
    }
}

/// A builder for [`DescribeConnectorOperationInput`](crate::operation::describe_connector_operation::DescribeConnectorOperationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConnectorOperationInputBuilder {
    pub(crate) connector_operation_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeConnectorOperationInputBuilder {
    /// <p>ARN of the connector operation to be described.</p>
    /// This field is required.
    pub fn connector_operation_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connector_operation_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the connector operation to be described.</p>
    pub fn set_connector_operation_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connector_operation_arn = input;
        self
    }
    /// <p>ARN of the connector operation to be described.</p>
    pub fn get_connector_operation_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.connector_operation_arn
    }
    /// Consumes the builder and constructs a [`DescribeConnectorOperationInput`](crate::operation::describe_connector_operation::DescribeConnectorOperationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_connector_operation::DescribeConnectorOperationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_connector_operation::DescribeConnectorOperationInput {
            connector_operation_arn: self.connector_operation_arn,
        })
    }
}
