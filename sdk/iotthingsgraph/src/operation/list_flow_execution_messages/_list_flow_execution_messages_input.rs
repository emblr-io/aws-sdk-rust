// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFlowExecutionMessagesInput {
    /// <p>The ID of the flow execution.</p>
    pub flow_execution_id: ::std::option::Option<::std::string::String>,
    /// <p>The string that specifies the next page of results. Use this when you're paginating results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListFlowExecutionMessagesInput {
    /// <p>The ID of the flow execution.</p>
    pub fn flow_execution_id(&self) -> ::std::option::Option<&str> {
        self.flow_execution_id.as_deref()
    }
    /// <p>The string that specifies the next page of results. Use this when you're paginating results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListFlowExecutionMessagesInput {
    /// Creates a new builder-style object to manufacture [`ListFlowExecutionMessagesInput`](crate::operation::list_flow_execution_messages::ListFlowExecutionMessagesInput).
    pub fn builder() -> crate::operation::list_flow_execution_messages::builders::ListFlowExecutionMessagesInputBuilder {
        crate::operation::list_flow_execution_messages::builders::ListFlowExecutionMessagesInputBuilder::default()
    }
}

/// A builder for [`ListFlowExecutionMessagesInput`](crate::operation::list_flow_execution_messages::ListFlowExecutionMessagesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFlowExecutionMessagesInputBuilder {
    pub(crate) flow_execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListFlowExecutionMessagesInputBuilder {
    /// <p>The ID of the flow execution.</p>
    /// This field is required.
    pub fn flow_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the flow execution.</p>
    pub fn set_flow_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_execution_id = input;
        self
    }
    /// <p>The ID of the flow execution.</p>
    pub fn get_flow_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_execution_id
    }
    /// <p>The string that specifies the next page of results. Use this when you're paginating results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string that specifies the next page of results. Use this when you're paginating results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The string that specifies the next page of results. Use this when you're paginating results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListFlowExecutionMessagesInput`](crate::operation::list_flow_execution_messages::ListFlowExecutionMessagesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_flow_execution_messages::ListFlowExecutionMessagesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_flow_execution_messages::ListFlowExecutionMessagesInput {
            flow_execution_id: self.flow_execution_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
