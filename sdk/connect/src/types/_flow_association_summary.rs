// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about flow associations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FlowAssociationSummary {
    /// <p>The identifier of the resource.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the flow.</p>
    pub flow_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of resource association.</p>
    pub resource_type: ::std::option::Option<crate::types::ListFlowAssociationResourceType>,
}
impl FlowAssociationSummary {
    /// <p>The identifier of the resource.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>The identifier of the flow.</p>
    pub fn flow_id(&self) -> ::std::option::Option<&str> {
        self.flow_id.as_deref()
    }
    /// <p>The type of resource association.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::ListFlowAssociationResourceType> {
        self.resource_type.as_ref()
    }
}
impl FlowAssociationSummary {
    /// Creates a new builder-style object to manufacture [`FlowAssociationSummary`](crate::types::FlowAssociationSummary).
    pub fn builder() -> crate::types::builders::FlowAssociationSummaryBuilder {
        crate::types::builders::FlowAssociationSummaryBuilder::default()
    }
}

/// A builder for [`FlowAssociationSummary`](crate::types::FlowAssociationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FlowAssociationSummaryBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) flow_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ListFlowAssociationResourceType>,
}
impl FlowAssociationSummaryBuilder {
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
    /// <p>The type of resource association.</p>
    pub fn resource_type(mut self, input: crate::types::ListFlowAssociationResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of resource association.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ListFlowAssociationResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The type of resource association.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ListFlowAssociationResourceType> {
        &self.resource_type
    }
    /// Consumes the builder and constructs a [`FlowAssociationSummary`](crate::types::FlowAssociationSummary).
    pub fn build(self) -> crate::types::FlowAssociationSummary {
        crate::types::FlowAssociationSummary {
            resource_id: self.resource_id,
            flow_id: self.flow_id,
            resource_type: self.resource_type,
        }
    }
}
