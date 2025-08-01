// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a replica to be created.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateReplicationGroupMemberAction {
    /// <p>The Region where the new replica will be created.</p>
    pub region_name: ::std::string::String,
    /// <p>The KMS key that should be used for KMS encryption in the new replica. To specify a key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. Note that you should only provide this parameter if the key is different from the default DynamoDB KMS key <code>alias/aws/dynamodb</code>.</p>
    pub kms_master_key_id: ::std::option::Option<::std::string::String>,
    /// <p>Replica-specific provisioned throughput. If not specified, uses the source table's provisioned throughput settings.</p>
    pub provisioned_throughput_override: ::std::option::Option<crate::types::ProvisionedThroughputOverride>,
    /// <p>The maximum on-demand throughput settings for the specified replica table being created. You can only modify <code>MaxReadRequestUnits</code>, because you can't modify <code>MaxWriteRequestUnits</code> for individual replica tables.</p>
    pub on_demand_throughput_override: ::std::option::Option<crate::types::OnDemandThroughputOverride>,
    /// <p>Replica-specific global secondary index settings.</p>
    pub global_secondary_indexes: ::std::option::Option<::std::vec::Vec<crate::types::ReplicaGlobalSecondaryIndex>>,
    /// <p>Replica-specific table class. If not specified, uses the source table's table class.</p>
    pub table_class_override: ::std::option::Option<crate::types::TableClass>,
}
impl CreateReplicationGroupMemberAction {
    /// <p>The Region where the new replica will be created.</p>
    pub fn region_name(&self) -> &str {
        use std::ops::Deref;
        self.region_name.deref()
    }
    /// <p>The KMS key that should be used for KMS encryption in the new replica. To specify a key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. Note that you should only provide this parameter if the key is different from the default DynamoDB KMS key <code>alias/aws/dynamodb</code>.</p>
    pub fn kms_master_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_master_key_id.as_deref()
    }
    /// <p>Replica-specific provisioned throughput. If not specified, uses the source table's provisioned throughput settings.</p>
    pub fn provisioned_throughput_override(&self) -> ::std::option::Option<&crate::types::ProvisionedThroughputOverride> {
        self.provisioned_throughput_override.as_ref()
    }
    /// <p>The maximum on-demand throughput settings for the specified replica table being created. You can only modify <code>MaxReadRequestUnits</code>, because you can't modify <code>MaxWriteRequestUnits</code> for individual replica tables.</p>
    pub fn on_demand_throughput_override(&self) -> ::std::option::Option<&crate::types::OnDemandThroughputOverride> {
        self.on_demand_throughput_override.as_ref()
    }
    /// <p>Replica-specific global secondary index settings.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.global_secondary_indexes.is_none()`.
    pub fn global_secondary_indexes(&self) -> &[crate::types::ReplicaGlobalSecondaryIndex] {
        self.global_secondary_indexes.as_deref().unwrap_or_default()
    }
    /// <p>Replica-specific table class. If not specified, uses the source table's table class.</p>
    pub fn table_class_override(&self) -> ::std::option::Option<&crate::types::TableClass> {
        self.table_class_override.as_ref()
    }
}
impl CreateReplicationGroupMemberAction {
    /// Creates a new builder-style object to manufacture [`CreateReplicationGroupMemberAction`](crate::types::CreateReplicationGroupMemberAction).
    pub fn builder() -> crate::types::builders::CreateReplicationGroupMemberActionBuilder {
        crate::types::builders::CreateReplicationGroupMemberActionBuilder::default()
    }
}

/// A builder for [`CreateReplicationGroupMemberAction`](crate::types::CreateReplicationGroupMemberAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateReplicationGroupMemberActionBuilder {
    pub(crate) region_name: ::std::option::Option<::std::string::String>,
    pub(crate) kms_master_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) provisioned_throughput_override: ::std::option::Option<crate::types::ProvisionedThroughputOverride>,
    pub(crate) on_demand_throughput_override: ::std::option::Option<crate::types::OnDemandThroughputOverride>,
    pub(crate) global_secondary_indexes: ::std::option::Option<::std::vec::Vec<crate::types::ReplicaGlobalSecondaryIndex>>,
    pub(crate) table_class_override: ::std::option::Option<crate::types::TableClass>,
}
impl CreateReplicationGroupMemberActionBuilder {
    /// <p>The Region where the new replica will be created.</p>
    /// This field is required.
    pub fn region_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Region where the new replica will be created.</p>
    pub fn set_region_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region_name = input;
        self
    }
    /// <p>The Region where the new replica will be created.</p>
    pub fn get_region_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.region_name
    }
    /// <p>The KMS key that should be used for KMS encryption in the new replica. To specify a key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. Note that you should only provide this parameter if the key is different from the default DynamoDB KMS key <code>alias/aws/dynamodb</code>.</p>
    pub fn kms_master_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_master_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The KMS key that should be used for KMS encryption in the new replica. To specify a key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. Note that you should only provide this parameter if the key is different from the default DynamoDB KMS key <code>alias/aws/dynamodb</code>.</p>
    pub fn set_kms_master_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_master_key_id = input;
        self
    }
    /// <p>The KMS key that should be used for KMS encryption in the new replica. To specify a key, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. Note that you should only provide this parameter if the key is different from the default DynamoDB KMS key <code>alias/aws/dynamodb</code>.</p>
    pub fn get_kms_master_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_master_key_id
    }
    /// <p>Replica-specific provisioned throughput. If not specified, uses the source table's provisioned throughput settings.</p>
    pub fn provisioned_throughput_override(mut self, input: crate::types::ProvisionedThroughputOverride) -> Self {
        self.provisioned_throughput_override = ::std::option::Option::Some(input);
        self
    }
    /// <p>Replica-specific provisioned throughput. If not specified, uses the source table's provisioned throughput settings.</p>
    pub fn set_provisioned_throughput_override(mut self, input: ::std::option::Option<crate::types::ProvisionedThroughputOverride>) -> Self {
        self.provisioned_throughput_override = input;
        self
    }
    /// <p>Replica-specific provisioned throughput. If not specified, uses the source table's provisioned throughput settings.</p>
    pub fn get_provisioned_throughput_override(&self) -> &::std::option::Option<crate::types::ProvisionedThroughputOverride> {
        &self.provisioned_throughput_override
    }
    /// <p>The maximum on-demand throughput settings for the specified replica table being created. You can only modify <code>MaxReadRequestUnits</code>, because you can't modify <code>MaxWriteRequestUnits</code> for individual replica tables.</p>
    pub fn on_demand_throughput_override(mut self, input: crate::types::OnDemandThroughputOverride) -> Self {
        self.on_demand_throughput_override = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum on-demand throughput settings for the specified replica table being created. You can only modify <code>MaxReadRequestUnits</code>, because you can't modify <code>MaxWriteRequestUnits</code> for individual replica tables.</p>
    pub fn set_on_demand_throughput_override(mut self, input: ::std::option::Option<crate::types::OnDemandThroughputOverride>) -> Self {
        self.on_demand_throughput_override = input;
        self
    }
    /// <p>The maximum on-demand throughput settings for the specified replica table being created. You can only modify <code>MaxReadRequestUnits</code>, because you can't modify <code>MaxWriteRequestUnits</code> for individual replica tables.</p>
    pub fn get_on_demand_throughput_override(&self) -> &::std::option::Option<crate::types::OnDemandThroughputOverride> {
        &self.on_demand_throughput_override
    }
    /// Appends an item to `global_secondary_indexes`.
    ///
    /// To override the contents of this collection use [`set_global_secondary_indexes`](Self::set_global_secondary_indexes).
    ///
    /// <p>Replica-specific global secondary index settings.</p>
    pub fn global_secondary_indexes(mut self, input: crate::types::ReplicaGlobalSecondaryIndex) -> Self {
        let mut v = self.global_secondary_indexes.unwrap_or_default();
        v.push(input);
        self.global_secondary_indexes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Replica-specific global secondary index settings.</p>
    pub fn set_global_secondary_indexes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReplicaGlobalSecondaryIndex>>) -> Self {
        self.global_secondary_indexes = input;
        self
    }
    /// <p>Replica-specific global secondary index settings.</p>
    pub fn get_global_secondary_indexes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReplicaGlobalSecondaryIndex>> {
        &self.global_secondary_indexes
    }
    /// <p>Replica-specific table class. If not specified, uses the source table's table class.</p>
    pub fn table_class_override(mut self, input: crate::types::TableClass) -> Self {
        self.table_class_override = ::std::option::Option::Some(input);
        self
    }
    /// <p>Replica-specific table class. If not specified, uses the source table's table class.</p>
    pub fn set_table_class_override(mut self, input: ::std::option::Option<crate::types::TableClass>) -> Self {
        self.table_class_override = input;
        self
    }
    /// <p>Replica-specific table class. If not specified, uses the source table's table class.</p>
    pub fn get_table_class_override(&self) -> &::std::option::Option<crate::types::TableClass> {
        &self.table_class_override
    }
    /// Consumes the builder and constructs a [`CreateReplicationGroupMemberAction`](crate::types::CreateReplicationGroupMemberAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`region_name`](crate::types::builders::CreateReplicationGroupMemberActionBuilder::region_name)
    pub fn build(self) -> ::std::result::Result<crate::types::CreateReplicationGroupMemberAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CreateReplicationGroupMemberAction {
            region_name: self.region_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "region_name",
                    "region_name was not specified but it is required when building CreateReplicationGroupMemberAction",
                )
            })?,
            kms_master_key_id: self.kms_master_key_id,
            provisioned_throughput_override: self.provisioned_throughput_override,
            on_demand_throughput_override: self.on_demand_throughput_override,
            global_secondary_indexes: self.global_secondary_indexes,
            table_class_override: self.table_class_override,
        })
    }
}
