// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateContainerServiceOutput {
    /// <p>An object that describes a container service.</p>
    pub container_service: ::std::option::Option<crate::types::ContainerService>,
    _request_id: Option<String>,
}
impl UpdateContainerServiceOutput {
    /// <p>An object that describes a container service.</p>
    pub fn container_service(&self) -> ::std::option::Option<&crate::types::ContainerService> {
        self.container_service.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateContainerServiceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateContainerServiceOutput {
    /// Creates a new builder-style object to manufacture [`UpdateContainerServiceOutput`](crate::operation::update_container_service::UpdateContainerServiceOutput).
    pub fn builder() -> crate::operation::update_container_service::builders::UpdateContainerServiceOutputBuilder {
        crate::operation::update_container_service::builders::UpdateContainerServiceOutputBuilder::default()
    }
}

/// A builder for [`UpdateContainerServiceOutput`](crate::operation::update_container_service::UpdateContainerServiceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateContainerServiceOutputBuilder {
    pub(crate) container_service: ::std::option::Option<crate::types::ContainerService>,
    _request_id: Option<String>,
}
impl UpdateContainerServiceOutputBuilder {
    /// <p>An object that describes a container service.</p>
    pub fn container_service(mut self, input: crate::types::ContainerService) -> Self {
        self.container_service = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that describes a container service.</p>
    pub fn set_container_service(mut self, input: ::std::option::Option<crate::types::ContainerService>) -> Self {
        self.container_service = input;
        self
    }
    /// <p>An object that describes a container service.</p>
    pub fn get_container_service(&self) -> &::std::option::Option<crate::types::ContainerService> {
        &self.container_service
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateContainerServiceOutput`](crate::operation::update_container_service::UpdateContainerServiceOutput).
    pub fn build(self) -> crate::operation::update_container_service::UpdateContainerServiceOutput {
        crate::operation::update_container_service::UpdateContainerServiceOutput {
            container_service: self.container_service,
            _request_id: self._request_id,
        }
    }
}
