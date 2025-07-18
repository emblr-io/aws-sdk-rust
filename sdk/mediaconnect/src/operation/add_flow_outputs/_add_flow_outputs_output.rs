// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddFlowOutputsOutput {
    /// <p>The ARN of the flow that these outputs were added to.</p>
    pub flow_arn: ::std::option::Option<::std::string::String>,
    /// <p>The details of the newly added outputs.</p>
    pub outputs: ::std::option::Option<::std::vec::Vec<crate::types::Output>>,
    _request_id: Option<String>,
}
impl AddFlowOutputsOutput {
    /// <p>The ARN of the flow that these outputs were added to.</p>
    pub fn flow_arn(&self) -> ::std::option::Option<&str> {
        self.flow_arn.as_deref()
    }
    /// <p>The details of the newly added outputs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.outputs.is_none()`.
    pub fn outputs(&self) -> &[crate::types::Output] {
        self.outputs.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for AddFlowOutputsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AddFlowOutputsOutput {
    /// Creates a new builder-style object to manufacture [`AddFlowOutputsOutput`](crate::operation::add_flow_outputs::AddFlowOutputsOutput).
    pub fn builder() -> crate::operation::add_flow_outputs::builders::AddFlowOutputsOutputBuilder {
        crate::operation::add_flow_outputs::builders::AddFlowOutputsOutputBuilder::default()
    }
}

/// A builder for [`AddFlowOutputsOutput`](crate::operation::add_flow_outputs::AddFlowOutputsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddFlowOutputsOutputBuilder {
    pub(crate) flow_arn: ::std::option::Option<::std::string::String>,
    pub(crate) outputs: ::std::option::Option<::std::vec::Vec<crate::types::Output>>,
    _request_id: Option<String>,
}
impl AddFlowOutputsOutputBuilder {
    /// <p>The ARN of the flow that these outputs were added to.</p>
    pub fn flow_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the flow that these outputs were added to.</p>
    pub fn set_flow_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_arn = input;
        self
    }
    /// <p>The ARN of the flow that these outputs were added to.</p>
    pub fn get_flow_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_arn
    }
    /// Appends an item to `outputs`.
    ///
    /// To override the contents of this collection use [`set_outputs`](Self::set_outputs).
    ///
    /// <p>The details of the newly added outputs.</p>
    pub fn outputs(mut self, input: crate::types::Output) -> Self {
        let mut v = self.outputs.unwrap_or_default();
        v.push(input);
        self.outputs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The details of the newly added outputs.</p>
    pub fn set_outputs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Output>>) -> Self {
        self.outputs = input;
        self
    }
    /// <p>The details of the newly added outputs.</p>
    pub fn get_outputs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Output>> {
        &self.outputs
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AddFlowOutputsOutput`](crate::operation::add_flow_outputs::AddFlowOutputsOutput).
    pub fn build(self) -> crate::operation::add_flow_outputs::AddFlowOutputsOutput {
        crate::operation::add_flow_outputs::AddFlowOutputsOutput {
            flow_arn: self.flow_arn,
            outputs: self.outputs,
            _request_id: self._request_id,
        }
    }
}
