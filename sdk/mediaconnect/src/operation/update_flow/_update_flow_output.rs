// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateFlowOutput {
    /// <p>The updated flow.</p>
    pub flow: ::std::option::Option<crate::types::Flow>,
    _request_id: Option<String>,
}
impl UpdateFlowOutput {
    /// <p>The updated flow.</p>
    pub fn flow(&self) -> ::std::option::Option<&crate::types::Flow> {
        self.flow.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateFlowOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateFlowOutput {
    /// Creates a new builder-style object to manufacture [`UpdateFlowOutput`](crate::operation::update_flow::UpdateFlowOutput).
    pub fn builder() -> crate::operation::update_flow::builders::UpdateFlowOutputBuilder {
        crate::operation::update_flow::builders::UpdateFlowOutputBuilder::default()
    }
}

/// A builder for [`UpdateFlowOutput`](crate::operation::update_flow::UpdateFlowOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateFlowOutputBuilder {
    pub(crate) flow: ::std::option::Option<crate::types::Flow>,
    _request_id: Option<String>,
}
impl UpdateFlowOutputBuilder {
    /// <p>The updated flow.</p>
    pub fn flow(mut self, input: crate::types::Flow) -> Self {
        self.flow = ::std::option::Option::Some(input);
        self
    }
    /// <p>The updated flow.</p>
    pub fn set_flow(mut self, input: ::std::option::Option<crate::types::Flow>) -> Self {
        self.flow = input;
        self
    }
    /// <p>The updated flow.</p>
    pub fn get_flow(&self) -> &::std::option::Option<crate::types::Flow> {
        &self.flow
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateFlowOutput`](crate::operation::update_flow::UpdateFlowOutput).
    pub fn build(self) -> crate::operation::update_flow::UpdateFlowOutput {
        crate::operation::update_flow::UpdateFlowOutput {
            flow: self.flow,
            _request_id: self._request_id,
        }
    }
}
