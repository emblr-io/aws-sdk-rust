// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelComponentDeploymentOutput {
    /// <p>The detailed data of the component with the deployment that is being canceled.</p>
    pub component: ::std::option::Option<crate::types::Component>,
    _request_id: Option<String>,
}
impl CancelComponentDeploymentOutput {
    /// <p>The detailed data of the component with the deployment that is being canceled.</p>
    pub fn component(&self) -> ::std::option::Option<&crate::types::Component> {
        self.component.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CancelComponentDeploymentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CancelComponentDeploymentOutput {
    /// Creates a new builder-style object to manufacture [`CancelComponentDeploymentOutput`](crate::operation::cancel_component_deployment::CancelComponentDeploymentOutput).
    pub fn builder() -> crate::operation::cancel_component_deployment::builders::CancelComponentDeploymentOutputBuilder {
        crate::operation::cancel_component_deployment::builders::CancelComponentDeploymentOutputBuilder::default()
    }
}

/// A builder for [`CancelComponentDeploymentOutput`](crate::operation::cancel_component_deployment::CancelComponentDeploymentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelComponentDeploymentOutputBuilder {
    pub(crate) component: ::std::option::Option<crate::types::Component>,
    _request_id: Option<String>,
}
impl CancelComponentDeploymentOutputBuilder {
    /// <p>The detailed data of the component with the deployment that is being canceled.</p>
    /// This field is required.
    pub fn component(mut self, input: crate::types::Component) -> Self {
        self.component = ::std::option::Option::Some(input);
        self
    }
    /// <p>The detailed data of the component with the deployment that is being canceled.</p>
    pub fn set_component(mut self, input: ::std::option::Option<crate::types::Component>) -> Self {
        self.component = input;
        self
    }
    /// <p>The detailed data of the component with the deployment that is being canceled.</p>
    pub fn get_component(&self) -> &::std::option::Option<crate::types::Component> {
        &self.component
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CancelComponentDeploymentOutput`](crate::operation::cancel_component_deployment::CancelComponentDeploymentOutput).
    pub fn build(self) -> crate::operation::cancel_component_deployment::CancelComponentDeploymentOutput {
        crate::operation::cancel_component_deployment::CancelComponentDeploymentOutput {
            component: self.component,
            _request_id: self._request_id,
        }
    }
}
