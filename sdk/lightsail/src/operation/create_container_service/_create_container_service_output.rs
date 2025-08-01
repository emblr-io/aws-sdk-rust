// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateContainerServiceOutput {
    /// <p>An object that describes a container service.</p>
    pub container_service: ::std::option::Option<crate::types::ContainerService>,
    _request_id: Option<String>,
}
impl CreateContainerServiceOutput {
    /// <p>An object that describes a container service.</p>
    pub fn container_service(&self) -> ::std::option::Option<&crate::types::ContainerService> {
        self.container_service.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateContainerServiceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateContainerServiceOutput {
    /// Creates a new builder-style object to manufacture [`CreateContainerServiceOutput`](crate::operation::create_container_service::CreateContainerServiceOutput).
    pub fn builder() -> crate::operation::create_container_service::builders::CreateContainerServiceOutputBuilder {
        crate::operation::create_container_service::builders::CreateContainerServiceOutputBuilder::default()
    }
}

/// A builder for [`CreateContainerServiceOutput`](crate::operation::create_container_service::CreateContainerServiceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateContainerServiceOutputBuilder {
    pub(crate) container_service: ::std::option::Option<crate::types::ContainerService>,
    _request_id: Option<String>,
}
impl CreateContainerServiceOutputBuilder {
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
    /// Consumes the builder and constructs a [`CreateContainerServiceOutput`](crate::operation::create_container_service::CreateContainerServiceOutput).
    pub fn build(self) -> crate::operation::create_container_service::CreateContainerServiceOutput {
        crate::operation::create_container_service::CreateContainerServiceOutput {
            container_service: self.container_service,
            _request_id: self._request_id,
        }
    }
}
