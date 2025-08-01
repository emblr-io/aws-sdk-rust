// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFlowAssociationOutput {
    /// <p>The identifier of the resource.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the flow.</p>
    pub flow_id: ::std::option::Option<::std::string::String>,
    /// <p>A valid resource type.</p>
    pub resource_type: ::std::option::Option<crate::types::FlowAssociationResourceType>,
    _request_id: Option<String>,
}
impl GetFlowAssociationOutput {
    /// <p>The identifier of the resource.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>The identifier of the flow.</p>
    pub fn flow_id(&self) -> ::std::option::Option<&str> {
        self.flow_id.as_deref()
    }
    /// <p>A valid resource type.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::FlowAssociationResourceType> {
        self.resource_type.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetFlowAssociationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFlowAssociationOutput {
    /// Creates a new builder-style object to manufacture [`GetFlowAssociationOutput`](crate::operation::get_flow_association::GetFlowAssociationOutput).
    pub fn builder() -> crate::operation::get_flow_association::builders::GetFlowAssociationOutputBuilder {
        crate::operation::get_flow_association::builders::GetFlowAssociationOutputBuilder::default()
    }
}

/// A builder for [`GetFlowAssociationOutput`](crate::operation::get_flow_association::GetFlowAssociationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFlowAssociationOutputBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) flow_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::FlowAssociationResourceType>,
    _request_id: Option<String>,
}
impl GetFlowAssociationOutputBuilder {
    /// <p>The identifier of the resource.</p>
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the resource.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The identifier of the resource.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The identifier of the flow.</p>
    pub fn flow_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the flow.</p>
    pub fn set_flow_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_id = input;
        self
    }
    /// <p>The identifier of the flow.</p>
    pub fn get_flow_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_id
    }
    /// <p>A valid resource type.</p>
    pub fn resource_type(mut self, input: crate::types::FlowAssociationResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>A valid resource type.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::FlowAssociationResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>A valid resource type.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::FlowAssociationResourceType> {
        &self.resource_type
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetFlowAssociationOutput`](crate::operation::get_flow_association::GetFlowAssociationOutput).
    pub fn build(self) -> crate::operation::get_flow_association::GetFlowAssociationOutput {
        crate::operation::get_flow_association::GetFlowAssociationOutput {
            resource_id: self.resource_id,
            flow_id: self.flow_id,
            resource_type: self.resource_type,
            _request_id: self._request_id,
        }
    }
}
