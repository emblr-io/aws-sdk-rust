// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeContactFlowModuleOutput {
    /// <p>Information about the flow module.</p>
    pub contact_flow_module: ::std::option::Option<crate::types::ContactFlowModule>,
    _request_id: Option<String>,
}
impl DescribeContactFlowModuleOutput {
    /// <p>Information about the flow module.</p>
    pub fn contact_flow_module(&self) -> ::std::option::Option<&crate::types::ContactFlowModule> {
        self.contact_flow_module.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeContactFlowModuleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeContactFlowModuleOutput {
    /// Creates a new builder-style object to manufacture [`DescribeContactFlowModuleOutput`](crate::operation::describe_contact_flow_module::DescribeContactFlowModuleOutput).
    pub fn builder() -> crate::operation::describe_contact_flow_module::builders::DescribeContactFlowModuleOutputBuilder {
        crate::operation::describe_contact_flow_module::builders::DescribeContactFlowModuleOutputBuilder::default()
    }
}

/// A builder for [`DescribeContactFlowModuleOutput`](crate::operation::describe_contact_flow_module::DescribeContactFlowModuleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeContactFlowModuleOutputBuilder {
    pub(crate) contact_flow_module: ::std::option::Option<crate::types::ContactFlowModule>,
    _request_id: Option<String>,
}
impl DescribeContactFlowModuleOutputBuilder {
    /// <p>Information about the flow module.</p>
    pub fn contact_flow_module(mut self, input: crate::types::ContactFlowModule) -> Self {
        self.contact_flow_module = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the flow module.</p>
    pub fn set_contact_flow_module(mut self, input: ::std::option::Option<crate::types::ContactFlowModule>) -> Self {
        self.contact_flow_module = input;
        self
    }
    /// <p>Information about the flow module.</p>
    pub fn get_contact_flow_module(&self) -> &::std::option::Option<crate::types::ContactFlowModule> {
        &self.contact_flow_module
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeContactFlowModuleOutput`](crate::operation::describe_contact_flow_module::DescribeContactFlowModuleOutput).
    pub fn build(self) -> crate::operation::describe_contact_flow_module::DescribeContactFlowModuleOutput {
        crate::operation::describe_contact_flow_module::DescribeContactFlowModuleOutput {
            contact_flow_module: self.contact_flow_module,
            _request_id: self._request_id,
        }
    }
}
