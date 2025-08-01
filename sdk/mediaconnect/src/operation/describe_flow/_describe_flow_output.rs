// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFlowOutput {
    /// <p>The flow that you requested a description of.</p>
    pub flow: ::std::option::Option<crate::types::Flow>,
    /// <p>Any errors that apply currently to the flow. If there are no errors, MediaConnect will not include this field in the response.</p>
    pub messages: ::std::option::Option<crate::types::Messages>,
    _request_id: Option<String>,
}
impl DescribeFlowOutput {
    /// <p>The flow that you requested a description of.</p>
    pub fn flow(&self) -> ::std::option::Option<&crate::types::Flow> {
        self.flow.as_ref()
    }
    /// <p>Any errors that apply currently to the flow. If there are no errors, MediaConnect will not include this field in the response.</p>
    pub fn messages(&self) -> ::std::option::Option<&crate::types::Messages> {
        self.messages.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeFlowOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeFlowOutput {
    /// Creates a new builder-style object to manufacture [`DescribeFlowOutput`](crate::operation::describe_flow::DescribeFlowOutput).
    pub fn builder() -> crate::operation::describe_flow::builders::DescribeFlowOutputBuilder {
        crate::operation::describe_flow::builders::DescribeFlowOutputBuilder::default()
    }
}

/// A builder for [`DescribeFlowOutput`](crate::operation::describe_flow::DescribeFlowOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFlowOutputBuilder {
    pub(crate) flow: ::std::option::Option<crate::types::Flow>,
    pub(crate) messages: ::std::option::Option<crate::types::Messages>,
    _request_id: Option<String>,
}
impl DescribeFlowOutputBuilder {
    /// <p>The flow that you requested a description of.</p>
    pub fn flow(mut self, input: crate::types::Flow) -> Self {
        self.flow = ::std::option::Option::Some(input);
        self
    }
    /// <p>The flow that you requested a description of.</p>
    pub fn set_flow(mut self, input: ::std::option::Option<crate::types::Flow>) -> Self {
        self.flow = input;
        self
    }
    /// <p>The flow that you requested a description of.</p>
    pub fn get_flow(&self) -> &::std::option::Option<crate::types::Flow> {
        &self.flow
    }
    /// <p>Any errors that apply currently to the flow. If there are no errors, MediaConnect will not include this field in the response.</p>
    pub fn messages(mut self, input: crate::types::Messages) -> Self {
        self.messages = ::std::option::Option::Some(input);
        self
    }
    /// <p>Any errors that apply currently to the flow. If there are no errors, MediaConnect will not include this field in the response.</p>
    pub fn set_messages(mut self, input: ::std::option::Option<crate::types::Messages>) -> Self {
        self.messages = input;
        self
    }
    /// <p>Any errors that apply currently to the flow. If there are no errors, MediaConnect will not include this field in the response.</p>
    pub fn get_messages(&self) -> &::std::option::Option<crate::types::Messages> {
        &self.messages
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeFlowOutput`](crate::operation::describe_flow::DescribeFlowOutput).
    pub fn build(self) -> crate::operation::describe_flow::DescribeFlowOutput {
        crate::operation::describe_flow::DescribeFlowOutput {
            flow: self.flow,
            messages: self.messages,
            _request_id: self._request_id,
        }
    }
}
