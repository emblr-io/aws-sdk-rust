// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a condition that was satisfied. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-trace.html">Track each step in your prompt flow by viewing its trace in Amazon Bedrock</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct FlowTraceCondition {
    /// <p>The name of the condition.</p>
    pub condition_name: ::std::string::String,
}
impl FlowTraceCondition {
    /// <p>The name of the condition.</p>
    pub fn condition_name(&self) -> &str {
        use std::ops::Deref;
        self.condition_name.deref()
    }
}
impl ::std::fmt::Debug for FlowTraceCondition {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FlowTraceCondition");
        formatter.field("condition_name", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl FlowTraceCondition {
    /// Creates a new builder-style object to manufacture [`FlowTraceCondition`](crate::types::FlowTraceCondition).
    pub fn builder() -> crate::types::builders::FlowTraceConditionBuilder {
        crate::types::builders::FlowTraceConditionBuilder::default()
    }
}

/// A builder for [`FlowTraceCondition`](crate::types::FlowTraceCondition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct FlowTraceConditionBuilder {
    pub(crate) condition_name: ::std::option::Option<::std::string::String>,
}
impl FlowTraceConditionBuilder {
    /// <p>The name of the condition.</p>
    /// This field is required.
    pub fn condition_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.condition_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the condition.</p>
    pub fn set_condition_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.condition_name = input;
        self
    }
    /// <p>The name of the condition.</p>
    pub fn get_condition_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.condition_name
    }
    /// Consumes the builder and constructs a [`FlowTraceCondition`](crate::types::FlowTraceCondition).
    /// This method will fail if any of the following fields are not set:
    /// - [`condition_name`](crate::types::builders::FlowTraceConditionBuilder::condition_name)
    pub fn build(self) -> ::std::result::Result<crate::types::FlowTraceCondition, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FlowTraceCondition {
            condition_name: self.condition_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "condition_name",
                    "condition_name was not specified but it is required when building FlowTraceCondition",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for FlowTraceConditionBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FlowTraceConditionBuilder");
        formatter.field("condition_name", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
