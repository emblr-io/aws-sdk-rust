// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::update_table_replica_auto_scaling::_update_table_replica_auto_scaling_output::UpdateTableReplicaAutoScalingOutputBuilder;

pub use crate::operation::update_table_replica_auto_scaling::_update_table_replica_auto_scaling_input::UpdateTableReplicaAutoScalingInputBuilder;

impl crate::operation::update_table_replica_auto_scaling::builders::UpdateTableReplicaAutoScalingInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.update_table_replica_auto_scaling();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `UpdateTableReplicaAutoScaling`.
///
/// <p>Updates auto scaling settings on your global tables at once.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct UpdateTableReplicaAutoScalingFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::update_table_replica_auto_scaling::builders::UpdateTableReplicaAutoScalingInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingOutput,
        crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingError,
    > for UpdateTableReplicaAutoScalingFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingOutput,
            crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl UpdateTableReplicaAutoScalingFluentBuilder {
    /// Creates a new `UpdateTableReplicaAutoScalingFluentBuilder`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the UpdateTableReplicaAutoScaling as a reference.
    pub fn as_input(&self) -> &crate::operation::update_table_replica_auto_scaling::builders::UpdateTableReplicaAutoScalingInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScaling::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScaling::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingOutput,
        crate::operation::update_table_replica_auto_scaling::UpdateTableReplicaAutoScalingError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl ::std::convert::Into<crate::config::Builder>) -> Self {
        self.set_config_override(::std::option::Option::Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: ::std::option::Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    ///
    /// Appends an item to `GlobalSecondaryIndexUpdates`.
    ///
    /// To override the contents of this collection use [`set_global_secondary_index_updates`](Self::set_global_secondary_index_updates).
    ///
    /// <p>Represents the auto scaling settings of the global secondary indexes of the replica to be updated.</p>
    pub fn global_secondary_index_updates(mut self, input: crate::types::GlobalSecondaryIndexAutoScalingUpdate) -> Self {
        self.inner = self.inner.global_secondary_index_updates(input);
        self
    }
    /// <p>Represents the auto scaling settings of the global secondary indexes of the replica to be updated.</p>
    pub fn set_global_secondary_index_updates(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::GlobalSecondaryIndexAutoScalingUpdate>>,
    ) -> Self {
        self.inner = self.inner.set_global_secondary_index_updates(input);
        self
    }
    /// <p>Represents the auto scaling settings of the global secondary indexes of the replica to be updated.</p>
    pub fn get_global_secondary_index_updates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GlobalSecondaryIndexAutoScalingUpdate>> {
        self.inner.get_global_secondary_index_updates()
    }
    /// <p>The name of the global table to be updated. You can also provide the Amazon Resource Name (ARN) of the table in this parameter.</p>
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.table_name(input.into());
        self
    }
    /// <p>The name of the global table to be updated. You can also provide the Amazon Resource Name (ARN) of the table in this parameter.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_table_name(input);
        self
    }
    /// <p>The name of the global table to be updated. You can also provide the Amazon Resource Name (ARN) of the table in this parameter.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_table_name()
    }
    /// <p>Represents the auto scaling settings to be modified for a global table or global secondary index.</p>
    pub fn provisioned_write_capacity_auto_scaling_update(mut self, input: crate::types::AutoScalingSettingsUpdate) -> Self {
        self.inner = self.inner.provisioned_write_capacity_auto_scaling_update(input);
        self
    }
    /// <p>Represents the auto scaling settings to be modified for a global table or global secondary index.</p>
    pub fn set_provisioned_write_capacity_auto_scaling_update(
        mut self,
        input: ::std::option::Option<crate::types::AutoScalingSettingsUpdate>,
    ) -> Self {
        self.inner = self.inner.set_provisioned_write_capacity_auto_scaling_update(input);
        self
    }
    /// <p>Represents the auto scaling settings to be modified for a global table or global secondary index.</p>
    pub fn get_provisioned_write_capacity_auto_scaling_update(&self) -> &::std::option::Option<crate::types::AutoScalingSettingsUpdate> {
        self.inner.get_provisioned_write_capacity_auto_scaling_update()
    }
    ///
    /// Appends an item to `ReplicaUpdates`.
    ///
    /// To override the contents of this collection use [`set_replica_updates`](Self::set_replica_updates).
    ///
    /// <p>Represents the auto scaling settings of replicas of the table that will be modified.</p>
    pub fn replica_updates(mut self, input: crate::types::ReplicaAutoScalingUpdate) -> Self {
        self.inner = self.inner.replica_updates(input);
        self
    }
    /// <p>Represents the auto scaling settings of replicas of the table that will be modified.</p>
    pub fn set_replica_updates(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReplicaAutoScalingUpdate>>) -> Self {
        self.inner = self.inner.set_replica_updates(input);
        self
    }
    /// <p>Represents the auto scaling settings of replicas of the table that will be modified.</p>
    pub fn get_replica_updates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReplicaAutoScalingUpdate>> {
        self.inner.get_replica_updates()
    }
}
