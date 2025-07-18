// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the service and cluster names used to identify an Amazon ECS deployment's target.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EcsService {
    /// <p>The name of the target Amazon ECS service.</p>
    pub service_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the cluster that the Amazon ECS service is associated with.</p>
    pub cluster_name: ::std::option::Option<::std::string::String>,
}
impl EcsService {
    /// <p>The name of the target Amazon ECS service.</p>
    pub fn service_name(&self) -> ::std::option::Option<&str> {
        self.service_name.as_deref()
    }
    /// <p>The name of the cluster that the Amazon ECS service is associated with.</p>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
}
impl EcsService {
    /// Creates a new builder-style object to manufacture [`EcsService`](crate::types::EcsService).
    pub fn builder() -> crate::types::builders::EcsServiceBuilder {
        crate::types::builders::EcsServiceBuilder::default()
    }
}

/// A builder for [`EcsService`](crate::types::EcsService).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EcsServiceBuilder {
    pub(crate) service_name: ::std::option::Option<::std::string::String>,
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
}
impl EcsServiceBuilder {
    /// <p>The name of the target Amazon ECS service.</p>
    pub fn service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the target Amazon ECS service.</p>
    pub fn set_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_name = input;
        self
    }
    /// <p>The name of the target Amazon ECS service.</p>
    pub fn get_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_name
    }
    /// <p>The name of the cluster that the Amazon ECS service is associated with.</p>
    pub fn cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster that the Amazon ECS service is associated with.</p>
    pub fn set_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_name = input;
        self
    }
    /// <p>The name of the cluster that the Amazon ECS service is associated with.</p>
    pub fn get_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_name
    }
    /// Consumes the builder and constructs a [`EcsService`](crate::types::EcsService).
    pub fn build(self) -> crate::types::EcsService {
        crate::types::EcsService {
            service_name: self.service_name,
            cluster_name: self.cluster_name,
        }
    }
}
