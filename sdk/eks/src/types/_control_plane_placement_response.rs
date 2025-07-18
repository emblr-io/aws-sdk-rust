// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The placement configuration for all the control plane instances of your local Amazon EKS cluster on an Amazon Web Services Outpost. For more information, see <a href="https://docs.aws.amazon.com/eks/latest/userguide/eks-outposts-capacity-considerations.html">Capacity considerations</a> in the <i>Amazon EKS User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ControlPlanePlacementResponse {
    /// <p>The name of the placement group for the Kubernetes control plane instances.</p>
    pub group_name: ::std::option::Option<::std::string::String>,
}
impl ControlPlanePlacementResponse {
    /// <p>The name of the placement group for the Kubernetes control plane instances.</p>
    pub fn group_name(&self) -> ::std::option::Option<&str> {
        self.group_name.as_deref()
    }
}
impl ControlPlanePlacementResponse {
    /// Creates a new builder-style object to manufacture [`ControlPlanePlacementResponse`](crate::types::ControlPlanePlacementResponse).
    pub fn builder() -> crate::types::builders::ControlPlanePlacementResponseBuilder {
        crate::types::builders::ControlPlanePlacementResponseBuilder::default()
    }
}

/// A builder for [`ControlPlanePlacementResponse`](crate::types::ControlPlanePlacementResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ControlPlanePlacementResponseBuilder {
    pub(crate) group_name: ::std::option::Option<::std::string::String>,
}
impl ControlPlanePlacementResponseBuilder {
    /// <p>The name of the placement group for the Kubernetes control plane instances.</p>
    pub fn group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the placement group for the Kubernetes control plane instances.</p>
    pub fn set_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_name = input;
        self
    }
    /// <p>The name of the placement group for the Kubernetes control plane instances.</p>
    pub fn get_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_name
    }
    /// Consumes the builder and constructs a [`ControlPlanePlacementResponse`](crate::types::ControlPlanePlacementResponse).
    pub fn build(self) -> crate::types::ControlPlanePlacementResponse {
        crate::types::ControlPlanePlacementResponse { group_name: self.group_name }
    }
}
