// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration of a connection between a condition node and another node.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FlowConditionalConnectionConfiguration {
    /// <p>The condition that triggers this connection. For more information about how to write conditions, see the <b>Condition</b> node type in the <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/node-types.html">Node types</a> topic in the Amazon Bedrock User Guide.</p>
    pub condition: ::std::string::String,
}
impl FlowConditionalConnectionConfiguration {
    /// <p>The condition that triggers this connection. For more information about how to write conditions, see the <b>Condition</b> node type in the <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/node-types.html">Node types</a> topic in the Amazon Bedrock User Guide.</p>
    pub fn condition(&self) -> &str {
        use std::ops::Deref;
        self.condition.deref()
    }
}
impl FlowConditionalConnectionConfiguration {
    /// Creates a new builder-style object to manufacture [`FlowConditionalConnectionConfiguration`](crate::types::FlowConditionalConnectionConfiguration).
    pub fn builder() -> crate::types::builders::FlowConditionalConnectionConfigurationBuilder {
        crate::types::builders::FlowConditionalConnectionConfigurationBuilder::default()
    }
}

/// A builder for [`FlowConditionalConnectionConfiguration`](crate::types::FlowConditionalConnectionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FlowConditionalConnectionConfigurationBuilder {
    pub(crate) condition: ::std::option::Option<::std::string::String>,
}
impl FlowConditionalConnectionConfigurationBuilder {
    /// <p>The condition that triggers this connection. For more information about how to write conditions, see the <b>Condition</b> node type in the <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/node-types.html">Node types</a> topic in the Amazon Bedrock User Guide.</p>
    /// This field is required.
    pub fn condition(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.condition = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The condition that triggers this connection. For more information about how to write conditions, see the <b>Condition</b> node type in the <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/node-types.html">Node types</a> topic in the Amazon Bedrock User Guide.</p>
    pub fn set_condition(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.condition = input;
        self
    }
    /// <p>The condition that triggers this connection. For more information about how to write conditions, see the <b>Condition</b> node type in the <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/node-types.html">Node types</a> topic in the Amazon Bedrock User Guide.</p>
    pub fn get_condition(&self) -> &::std::option::Option<::std::string::String> {
        &self.condition
    }
    /// Consumes the builder and constructs a [`FlowConditionalConnectionConfiguration`](crate::types::FlowConditionalConnectionConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`condition`](crate::types::builders::FlowConditionalConnectionConfigurationBuilder::condition)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::FlowConditionalConnectionConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FlowConditionalConnectionConfiguration {
            condition: self.condition.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "condition",
                    "condition was not specified but it is required when building FlowConditionalConnectionConfiguration",
                )
            })?,
        })
    }
}
