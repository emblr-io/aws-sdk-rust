// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelFlowExecutionsInput {
    /// <p>The name of a flow with active runs that you want to cancel.</p>
    pub flow_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of each active run to cancel. These runs must belong to the flow you specify in your request.</p>
    /// <p>If you omit this parameter, your request ends all active runs that belong to the flow.</p>
    pub execution_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CancelFlowExecutionsInput {
    /// <p>The name of a flow with active runs that you want to cancel.</p>
    pub fn flow_name(&self) -> ::std::option::Option<&str> {
        self.flow_name.as_deref()
    }
    /// <p>The ID of each active run to cancel. These runs must belong to the flow you specify in your request.</p>
    /// <p>If you omit this parameter, your request ends all active runs that belong to the flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.execution_ids.is_none()`.
    pub fn execution_ids(&self) -> &[::std::string::String] {
        self.execution_ids.as_deref().unwrap_or_default()
    }
}
impl CancelFlowExecutionsInput {
    /// Creates a new builder-style object to manufacture [`CancelFlowExecutionsInput`](crate::operation::cancel_flow_executions::CancelFlowExecutionsInput).
    pub fn builder() -> crate::operation::cancel_flow_executions::builders::CancelFlowExecutionsInputBuilder {
        crate::operation::cancel_flow_executions::builders::CancelFlowExecutionsInputBuilder::default()
    }
}

/// A builder for [`CancelFlowExecutionsInput`](crate::operation::cancel_flow_executions::CancelFlowExecutionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelFlowExecutionsInputBuilder {
    pub(crate) flow_name: ::std::option::Option<::std::string::String>,
    pub(crate) execution_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CancelFlowExecutionsInputBuilder {
    /// <p>The name of a flow with active runs that you want to cancel.</p>
    /// This field is required.
    pub fn flow_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a flow with active runs that you want to cancel.</p>
    pub fn set_flow_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_name = input;
        self
    }
    /// <p>The name of a flow with active runs that you want to cancel.</p>
    pub fn get_flow_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_name
    }
    /// Appends an item to `execution_ids`.
    ///
    /// To override the contents of this collection use [`set_execution_ids`](Self::set_execution_ids).
    ///
    /// <p>The ID of each active run to cancel. These runs must belong to the flow you specify in your request.</p>
    /// <p>If you omit this parameter, your request ends all active runs that belong to the flow.</p>
    pub fn execution_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.execution_ids.unwrap_or_default();
        v.push(input.into());
        self.execution_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ID of each active run to cancel. These runs must belong to the flow you specify in your request.</p>
    /// <p>If you omit this parameter, your request ends all active runs that belong to the flow.</p>
    pub fn set_execution_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.execution_ids = input;
        self
    }
    /// <p>The ID of each active run to cancel. These runs must belong to the flow you specify in your request.</p>
    /// <p>If you omit this parameter, your request ends all active runs that belong to the flow.</p>
    pub fn get_execution_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.execution_ids
    }
    /// Consumes the builder and constructs a [`CancelFlowExecutionsInput`](crate::operation::cancel_flow_executions::CancelFlowExecutionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_flow_executions::CancelFlowExecutionsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::cancel_flow_executions::CancelFlowExecutionsInput {
            flow_name: self.flow_name,
            execution_ids: self.execution_ids,
        })
    }
}
