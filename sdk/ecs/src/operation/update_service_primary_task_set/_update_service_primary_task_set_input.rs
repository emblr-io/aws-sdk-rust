// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateServicePrimaryTaskSetInput {
    /// <p>The short name or full Amazon Resource Name (ARN) of the cluster that hosts the service that the task set exists in.</p>
    pub cluster: ::std::option::Option<::std::string::String>,
    /// <p>The short name or full Amazon Resource Name (ARN) of the service that the task set exists in.</p>
    pub service: ::std::option::Option<::std::string::String>,
    /// <p>The short name or full Amazon Resource Name (ARN) of the task set to set as the primary task set in the deployment.</p>
    pub primary_task_set: ::std::option::Option<::std::string::String>,
}
impl UpdateServicePrimaryTaskSetInput {
    /// <p>The short name or full Amazon Resource Name (ARN) of the cluster that hosts the service that the task set exists in.</p>
    pub fn cluster(&self) -> ::std::option::Option<&str> {
        self.cluster.as_deref()
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the service that the task set exists in.</p>
    pub fn service(&self) -> ::std::option::Option<&str> {
        self.service.as_deref()
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the task set to set as the primary task set in the deployment.</p>
    pub fn primary_task_set(&self) -> ::std::option::Option<&str> {
        self.primary_task_set.as_deref()
    }
}
impl UpdateServicePrimaryTaskSetInput {
    /// Creates a new builder-style object to manufacture [`UpdateServicePrimaryTaskSetInput`](crate::operation::update_service_primary_task_set::UpdateServicePrimaryTaskSetInput).
    pub fn builder() -> crate::operation::update_service_primary_task_set::builders::UpdateServicePrimaryTaskSetInputBuilder {
        crate::operation::update_service_primary_task_set::builders::UpdateServicePrimaryTaskSetInputBuilder::default()
    }
}

/// A builder for [`UpdateServicePrimaryTaskSetInput`](crate::operation::update_service_primary_task_set::UpdateServicePrimaryTaskSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateServicePrimaryTaskSetInputBuilder {
    pub(crate) cluster: ::std::option::Option<::std::string::String>,
    pub(crate) service: ::std::option::Option<::std::string::String>,
    pub(crate) primary_task_set: ::std::option::Option<::std::string::String>,
}
impl UpdateServicePrimaryTaskSetInputBuilder {
    /// <p>The short name or full Amazon Resource Name (ARN) of the cluster that hosts the service that the task set exists in.</p>
    /// This field is required.
    pub fn cluster(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the cluster that hosts the service that the task set exists in.</p>
    pub fn set_cluster(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster = input;
        self
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the cluster that hosts the service that the task set exists in.</p>
    pub fn get_cluster(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the service that the task set exists in.</p>
    /// This field is required.
    pub fn service(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the service that the task set exists in.</p>
    pub fn set_service(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service = input;
        self
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the service that the task set exists in.</p>
    pub fn get_service(&self) -> &::std::option::Option<::std::string::String> {
        &self.service
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the task set to set as the primary task set in the deployment.</p>
    /// This field is required.
    pub fn primary_task_set(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.primary_task_set = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the task set to set as the primary task set in the deployment.</p>
    pub fn set_primary_task_set(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.primary_task_set = input;
        self
    }
    /// <p>The short name or full Amazon Resource Name (ARN) of the task set to set as the primary task set in the deployment.</p>
    pub fn get_primary_task_set(&self) -> &::std::option::Option<::std::string::String> {
        &self.primary_task_set
    }
    /// Consumes the builder and constructs a [`UpdateServicePrimaryTaskSetInput`](crate::operation::update_service_primary_task_set::UpdateServicePrimaryTaskSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_service_primary_task_set::UpdateServicePrimaryTaskSetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_service_primary_task_set::UpdateServicePrimaryTaskSetInput {
            cluster: self.cluster,
            service: self.service,
            primary_task_set: self.primary_task_set,
        })
    }
}
