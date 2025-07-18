// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the configuration of an OpenSearch cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsOpenSearchServiceDomainClusterConfigDetails {
    /// <p>The number of data nodes to use in the OpenSearch domain.</p>
    pub instance_count: ::std::option::Option<i32>,
    /// <p>Whether UltraWarm is enabled.</p>
    pub warm_enabled: ::std::option::Option<bool>,
    /// <p>The number of UltraWarm instances.</p>
    pub warm_count: ::std::option::Option<i32>,
    /// <p>Whether to use a dedicated master node for the OpenSearch domain. A dedicated master node performs cluster management tasks, but does not hold data or respond to data upload requests.</p>
    pub dedicated_master_enabled: ::std::option::Option<bool>,
    /// <p>Configuration options for zone awareness. Provided if <code>ZoneAwarenessEnabled</code> is <code>true</code>.</p>
    pub zone_awareness_config: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails>,
    /// <p>The number of instances to use for the master node. If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub dedicated_master_count: ::std::option::Option<i32>,
    /// <p>The instance type for your data nodes.</p>
    /// <p>For a list of valid values, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html">Supported instance types in Amazon OpenSearch Service</a> in the <i>Amazon OpenSearch Service Developer Guide</i>.</p>
    pub instance_type: ::std::option::Option<::std::string::String>,
    /// <p>The type of UltraWarm instance.</p>
    pub warm_type: ::std::option::Option<::std::string::String>,
    /// <p>Whether to enable zone awareness for the OpenSearch domain. When zone awareness is enabled, OpenSearch Service allocates the cluster's nodes and replica index shards across Availability Zones (AZs) in the same Region. This prevents data loss and minimizes downtime if a node or data center fails.</p>
    pub zone_awareness_enabled: ::std::option::Option<bool>,
    /// <p>The hardware configuration of the computer that hosts the dedicated master node.</p>
    /// <p>If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub dedicated_master_type: ::std::option::Option<::std::string::String>,
}
impl AwsOpenSearchServiceDomainClusterConfigDetails {
    /// <p>The number of data nodes to use in the OpenSearch domain.</p>
    pub fn instance_count(&self) -> ::std::option::Option<i32> {
        self.instance_count
    }
    /// <p>Whether UltraWarm is enabled.</p>
    pub fn warm_enabled(&self) -> ::std::option::Option<bool> {
        self.warm_enabled
    }
    /// <p>The number of UltraWarm instances.</p>
    pub fn warm_count(&self) -> ::std::option::Option<i32> {
        self.warm_count
    }
    /// <p>Whether to use a dedicated master node for the OpenSearch domain. A dedicated master node performs cluster management tasks, but does not hold data or respond to data upload requests.</p>
    pub fn dedicated_master_enabled(&self) -> ::std::option::Option<bool> {
        self.dedicated_master_enabled
    }
    /// <p>Configuration options for zone awareness. Provided if <code>ZoneAwarenessEnabled</code> is <code>true</code>.</p>
    pub fn zone_awareness_config(&self) -> ::std::option::Option<&crate::types::AwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails> {
        self.zone_awareness_config.as_ref()
    }
    /// <p>The number of instances to use for the master node. If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub fn dedicated_master_count(&self) -> ::std::option::Option<i32> {
        self.dedicated_master_count
    }
    /// <p>The instance type for your data nodes.</p>
    /// <p>For a list of valid values, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html">Supported instance types in Amazon OpenSearch Service</a> in the <i>Amazon OpenSearch Service Developer Guide</i>.</p>
    pub fn instance_type(&self) -> ::std::option::Option<&str> {
        self.instance_type.as_deref()
    }
    /// <p>The type of UltraWarm instance.</p>
    pub fn warm_type(&self) -> ::std::option::Option<&str> {
        self.warm_type.as_deref()
    }
    /// <p>Whether to enable zone awareness for the OpenSearch domain. When zone awareness is enabled, OpenSearch Service allocates the cluster's nodes and replica index shards across Availability Zones (AZs) in the same Region. This prevents data loss and minimizes downtime if a node or data center fails.</p>
    pub fn zone_awareness_enabled(&self) -> ::std::option::Option<bool> {
        self.zone_awareness_enabled
    }
    /// <p>The hardware configuration of the computer that hosts the dedicated master node.</p>
    /// <p>If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub fn dedicated_master_type(&self) -> ::std::option::Option<&str> {
        self.dedicated_master_type.as_deref()
    }
}
impl AwsOpenSearchServiceDomainClusterConfigDetails {
    /// Creates a new builder-style object to manufacture [`AwsOpenSearchServiceDomainClusterConfigDetails`](crate::types::AwsOpenSearchServiceDomainClusterConfigDetails).
    pub fn builder() -> crate::types::builders::AwsOpenSearchServiceDomainClusterConfigDetailsBuilder {
        crate::types::builders::AwsOpenSearchServiceDomainClusterConfigDetailsBuilder::default()
    }
}

/// A builder for [`AwsOpenSearchServiceDomainClusterConfigDetails`](crate::types::AwsOpenSearchServiceDomainClusterConfigDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsOpenSearchServiceDomainClusterConfigDetailsBuilder {
    pub(crate) instance_count: ::std::option::Option<i32>,
    pub(crate) warm_enabled: ::std::option::Option<bool>,
    pub(crate) warm_count: ::std::option::Option<i32>,
    pub(crate) dedicated_master_enabled: ::std::option::Option<bool>,
    pub(crate) zone_awareness_config: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails>,
    pub(crate) dedicated_master_count: ::std::option::Option<i32>,
    pub(crate) instance_type: ::std::option::Option<::std::string::String>,
    pub(crate) warm_type: ::std::option::Option<::std::string::String>,
    pub(crate) zone_awareness_enabled: ::std::option::Option<bool>,
    pub(crate) dedicated_master_type: ::std::option::Option<::std::string::String>,
}
impl AwsOpenSearchServiceDomainClusterConfigDetailsBuilder {
    /// <p>The number of data nodes to use in the OpenSearch domain.</p>
    pub fn instance_count(mut self, input: i32) -> Self {
        self.instance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of data nodes to use in the OpenSearch domain.</p>
    pub fn set_instance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.instance_count = input;
        self
    }
    /// <p>The number of data nodes to use in the OpenSearch domain.</p>
    pub fn get_instance_count(&self) -> &::std::option::Option<i32> {
        &self.instance_count
    }
    /// <p>Whether UltraWarm is enabled.</p>
    pub fn warm_enabled(mut self, input: bool) -> Self {
        self.warm_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether UltraWarm is enabled.</p>
    pub fn set_warm_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.warm_enabled = input;
        self
    }
    /// <p>Whether UltraWarm is enabled.</p>
    pub fn get_warm_enabled(&self) -> &::std::option::Option<bool> {
        &self.warm_enabled
    }
    /// <p>The number of UltraWarm instances.</p>
    pub fn warm_count(mut self, input: i32) -> Self {
        self.warm_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of UltraWarm instances.</p>
    pub fn set_warm_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.warm_count = input;
        self
    }
    /// <p>The number of UltraWarm instances.</p>
    pub fn get_warm_count(&self) -> &::std::option::Option<i32> {
        &self.warm_count
    }
    /// <p>Whether to use a dedicated master node for the OpenSearch domain. A dedicated master node performs cluster management tasks, but does not hold data or respond to data upload requests.</p>
    pub fn dedicated_master_enabled(mut self, input: bool) -> Self {
        self.dedicated_master_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to use a dedicated master node for the OpenSearch domain. A dedicated master node performs cluster management tasks, but does not hold data or respond to data upload requests.</p>
    pub fn set_dedicated_master_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dedicated_master_enabled = input;
        self
    }
    /// <p>Whether to use a dedicated master node for the OpenSearch domain. A dedicated master node performs cluster management tasks, but does not hold data or respond to data upload requests.</p>
    pub fn get_dedicated_master_enabled(&self) -> &::std::option::Option<bool> {
        &self.dedicated_master_enabled
    }
    /// <p>Configuration options for zone awareness. Provided if <code>ZoneAwarenessEnabled</code> is <code>true</code>.</p>
    pub fn zone_awareness_config(mut self, input: crate::types::AwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails) -> Self {
        self.zone_awareness_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration options for zone awareness. Provided if <code>ZoneAwarenessEnabled</code> is <code>true</code>.</p>
    pub fn set_zone_awareness_config(
        mut self,
        input: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails>,
    ) -> Self {
        self.zone_awareness_config = input;
        self
    }
    /// <p>Configuration options for zone awareness. Provided if <code>ZoneAwarenessEnabled</code> is <code>true</code>.</p>
    pub fn get_zone_awareness_config(
        &self,
    ) -> &::std::option::Option<crate::types::AwsOpenSearchServiceDomainClusterConfigZoneAwarenessConfigDetails> {
        &self.zone_awareness_config
    }
    /// <p>The number of instances to use for the master node. If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub fn dedicated_master_count(mut self, input: i32) -> Self {
        self.dedicated_master_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of instances to use for the master node. If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub fn set_dedicated_master_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.dedicated_master_count = input;
        self
    }
    /// <p>The number of instances to use for the master node. If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub fn get_dedicated_master_count(&self) -> &::std::option::Option<i32> {
        &self.dedicated_master_count
    }
    /// <p>The instance type for your data nodes.</p>
    /// <p>For a list of valid values, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html">Supported instance types in Amazon OpenSearch Service</a> in the <i>Amazon OpenSearch Service Developer Guide</i>.</p>
    pub fn instance_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The instance type for your data nodes.</p>
    /// <p>For a list of valid values, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html">Supported instance types in Amazon OpenSearch Service</a> in the <i>Amazon OpenSearch Service Developer Guide</i>.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The instance type for your data nodes.</p>
    /// <p>For a list of valid values, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html">Supported instance types in Amazon OpenSearch Service</a> in the <i>Amazon OpenSearch Service Developer Guide</i>.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_type
    }
    /// <p>The type of UltraWarm instance.</p>
    pub fn warm_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.warm_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of UltraWarm instance.</p>
    pub fn set_warm_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.warm_type = input;
        self
    }
    /// <p>The type of UltraWarm instance.</p>
    pub fn get_warm_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.warm_type
    }
    /// <p>Whether to enable zone awareness for the OpenSearch domain. When zone awareness is enabled, OpenSearch Service allocates the cluster's nodes and replica index shards across Availability Zones (AZs) in the same Region. This prevents data loss and minimizes downtime if a node or data center fails.</p>
    pub fn zone_awareness_enabled(mut self, input: bool) -> Self {
        self.zone_awareness_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to enable zone awareness for the OpenSearch domain. When zone awareness is enabled, OpenSearch Service allocates the cluster's nodes and replica index shards across Availability Zones (AZs) in the same Region. This prevents data loss and minimizes downtime if a node or data center fails.</p>
    pub fn set_zone_awareness_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.zone_awareness_enabled = input;
        self
    }
    /// <p>Whether to enable zone awareness for the OpenSearch domain. When zone awareness is enabled, OpenSearch Service allocates the cluster's nodes and replica index shards across Availability Zones (AZs) in the same Region. This prevents data loss and minimizes downtime if a node or data center fails.</p>
    pub fn get_zone_awareness_enabled(&self) -> &::std::option::Option<bool> {
        &self.zone_awareness_enabled
    }
    /// <p>The hardware configuration of the computer that hosts the dedicated master node.</p>
    /// <p>If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub fn dedicated_master_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dedicated_master_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The hardware configuration of the computer that hosts the dedicated master node.</p>
    /// <p>If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub fn set_dedicated_master_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dedicated_master_type = input;
        self
    }
    /// <p>The hardware configuration of the computer that hosts the dedicated master node.</p>
    /// <p>If this attribute is specified, then <code>DedicatedMasterEnabled</code> must be <code>true</code>.</p>
    pub fn get_dedicated_master_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.dedicated_master_type
    }
    /// Consumes the builder and constructs a [`AwsOpenSearchServiceDomainClusterConfigDetails`](crate::types::AwsOpenSearchServiceDomainClusterConfigDetails).
    pub fn build(self) -> crate::types::AwsOpenSearchServiceDomainClusterConfigDetails {
        crate::types::AwsOpenSearchServiceDomainClusterConfigDetails {
            instance_count: self.instance_count,
            warm_enabled: self.warm_enabled,
            warm_count: self.warm_count,
            dedicated_master_enabled: self.dedicated_master_enabled,
            zone_awareness_config: self.zone_awareness_config,
            dedicated_master_count: self.dedicated_master_count,
            instance_type: self.instance_type,
            warm_type: self.warm_type,
            zone_awareness_enabled: self.zone_awareness_enabled,
            dedicated_master_type: self.dedicated_master_type,
        }
    }
}
