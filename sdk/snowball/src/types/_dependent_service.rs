// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The name and version of the service dependant on the requested service.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DependentService {
    /// <p>The name of the dependent service.</p>
    pub service_name: ::std::option::Option<crate::types::ServiceName>,
    /// <p>The version of the dependent service.</p>
    pub service_version: ::std::option::Option<crate::types::ServiceVersion>,
}
impl DependentService {
    /// <p>The name of the dependent service.</p>
    pub fn service_name(&self) -> ::std::option::Option<&crate::types::ServiceName> {
        self.service_name.as_ref()
    }
    /// <p>The version of the dependent service.</p>
    pub fn service_version(&self) -> ::std::option::Option<&crate::types::ServiceVersion> {
        self.service_version.as_ref()
    }
}
impl DependentService {
    /// Creates a new builder-style object to manufacture [`DependentService`](crate::types::DependentService).
    pub fn builder() -> crate::types::builders::DependentServiceBuilder {
        crate::types::builders::DependentServiceBuilder::default()
    }
}

/// A builder for [`DependentService`](crate::types::DependentService).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DependentServiceBuilder {
    pub(crate) service_name: ::std::option::Option<crate::types::ServiceName>,
    pub(crate) service_version: ::std::option::Option<crate::types::ServiceVersion>,
}
impl DependentServiceBuilder {
    /// <p>The name of the dependent service.</p>
    pub fn service_name(mut self, input: crate::types::ServiceName) -> Self {
        self.service_name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the dependent service.</p>
    pub fn set_service_name(mut self, input: ::std::option::Option<crate::types::ServiceName>) -> Self {
        self.service_name = input;
        self
    }
    /// <p>The name of the dependent service.</p>
    pub fn get_service_name(&self) -> &::std::option::Option<crate::types::ServiceName> {
        &self.service_name
    }
    /// <p>The version of the dependent service.</p>
    pub fn service_version(mut self, input: crate::types::ServiceVersion) -> Self {
        self.service_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the dependent service.</p>
    pub fn set_service_version(mut self, input: ::std::option::Option<crate::types::ServiceVersion>) -> Self {
        self.service_version = input;
        self
    }
    /// <p>The version of the dependent service.</p>
    pub fn get_service_version(&self) -> &::std::option::Option<crate::types::ServiceVersion> {
        &self.service_version
    }
    /// Consumes the builder and constructs a [`DependentService`](crate::types::DependentService).
    pub fn build(self) -> crate::types::DependentService {
        crate::types::DependentService {
            service_name: self.service_name,
            service_version: self.service_version,
        }
    }
}
