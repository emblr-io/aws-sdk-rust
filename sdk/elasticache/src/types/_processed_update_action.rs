// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Update action that has been processed for the corresponding apply/stop request</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProcessedUpdateAction {
    /// <p>The ID of the replication group</p>
    pub replication_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the cache cluster</p>
    pub cache_cluster_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique ID of the service update</p>
    pub service_update_name: ::std::option::Option<::std::string::String>,
    /// <p>The status of the update action on the Valkey or Redis OSS cluster</p>
    pub update_action_status: ::std::option::Option<crate::types::UpdateActionStatus>,
}
impl ProcessedUpdateAction {
    /// <p>The ID of the replication group</p>
    pub fn replication_group_id(&self) -> ::std::option::Option<&str> {
        self.replication_group_id.as_deref()
    }
    /// <p>The ID of the cache cluster</p>
    pub fn cache_cluster_id(&self) -> ::std::option::Option<&str> {
        self.cache_cluster_id.as_deref()
    }
    /// <p>The unique ID of the service update</p>
    pub fn service_update_name(&self) -> ::std::option::Option<&str> {
        self.service_update_name.as_deref()
    }
    /// <p>The status of the update action on the Valkey or Redis OSS cluster</p>
    pub fn update_action_status(&self) -> ::std::option::Option<&crate::types::UpdateActionStatus> {
        self.update_action_status.as_ref()
    }
}
impl ProcessedUpdateAction {
    /// Creates a new builder-style object to manufacture [`ProcessedUpdateAction`](crate::types::ProcessedUpdateAction).
    pub fn builder() -> crate::types::builders::ProcessedUpdateActionBuilder {
        crate::types::builders::ProcessedUpdateActionBuilder::default()
    }
}

/// A builder for [`ProcessedUpdateAction`](crate::types::ProcessedUpdateAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProcessedUpdateActionBuilder {
    pub(crate) replication_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) cache_cluster_id: ::std::option::Option<::std::string::String>,
    pub(crate) service_update_name: ::std::option::Option<::std::string::String>,
    pub(crate) update_action_status: ::std::option::Option<crate::types::UpdateActionStatus>,
}
impl ProcessedUpdateActionBuilder {
    /// <p>The ID of the replication group</p>
    pub fn replication_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the replication group</p>
    pub fn set_replication_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_group_id = input;
        self
    }
    /// <p>The ID of the replication group</p>
    pub fn get_replication_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_group_id
    }
    /// <p>The ID of the cache cluster</p>
    pub fn cache_cluster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cache_cluster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the cache cluster</p>
    pub fn set_cache_cluster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cache_cluster_id = input;
        self
    }
    /// <p>The ID of the cache cluster</p>
    pub fn get_cache_cluster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.cache_cluster_id
    }
    /// <p>The unique ID of the service update</p>
    pub fn service_update_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_update_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the service update</p>
    pub fn set_service_update_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_update_name = input;
        self
    }
    /// <p>The unique ID of the service update</p>
    pub fn get_service_update_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_update_name
    }
    /// <p>The status of the update action on the Valkey or Redis OSS cluster</p>
    pub fn update_action_status(mut self, input: crate::types::UpdateActionStatus) -> Self {
        self.update_action_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the update action on the Valkey or Redis OSS cluster</p>
    pub fn set_update_action_status(mut self, input: ::std::option::Option<crate::types::UpdateActionStatus>) -> Self {
        self.update_action_status = input;
        self
    }
    /// <p>The status of the update action on the Valkey or Redis OSS cluster</p>
    pub fn get_update_action_status(&self) -> &::std::option::Option<crate::types::UpdateActionStatus> {
        &self.update_action_status
    }
    /// Consumes the builder and constructs a [`ProcessedUpdateAction`](crate::types::ProcessedUpdateAction).
    pub fn build(self) -> crate::types::ProcessedUpdateAction {
        crate::types::ProcessedUpdateAction {
            replication_group_id: self.replication_group_id,
            cache_cluster_id: self.cache_cluster_id,
            service_update_name: self.service_update_name,
            update_action_status: self.update_action_status,
        }
    }
}
