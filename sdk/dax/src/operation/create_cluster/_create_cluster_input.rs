// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateClusterInput {
    /// <p>The cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p><b>Constraints:</b></p>
    /// <ul>
    /// <li>
    /// <p>A name must contain from 1 to 20 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>A name cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    pub cluster_name: ::std::option::Option<::std::string::String>,
    /// <p>The compute and memory capacity of the nodes in the cluster.</p>
    pub node_type: ::std::option::Option<::std::string::String>,
    /// <p>A description of the cluster.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The number of nodes in the DAX cluster. A replication factor of 1 will create a single-node cluster, without any read replicas. For additional fault tolerance, you can create a multiple node cluster with one or more read replicas. To do this, set <code>ReplicationFactor</code> to a number between 3 (one primary and two read replicas) and 10 (one primary and nine read replicas). <code>If the AvailabilityZones</code> parameter is provided, its length must equal the <code>ReplicationFactor</code>.</p><note>
    /// <p>AWS recommends that you have at least two read replicas per cluster.</p>
    /// </note>
    pub replication_factor: ::std::option::Option<i32>,
    /// <p>The Availability Zones (AZs) in which the cluster nodes will reside after the cluster has been created or updated. If provided, the length of this list must equal the <code>ReplicationFactor</code> parameter. If you omit this parameter, DAX will spread the nodes across Availability Zones for the highest availability.</p>
    pub availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the subnet group to be used for the replication group.</p><important>
    /// <p>DAX clusters can only run in an Amazon VPC environment. All of the subnets that you specify in a subnet group must exist in the same VPC.</p>
    /// </important>
    pub subnet_group_name: ::std::option::Option<::std::string::String>,
    /// <p>A list of security group IDs to be assigned to each node in the DAX cluster. (Each of the security group ID is system-generated.)</p>
    /// <p>If this parameter is not specified, DAX assigns the default VPC security group to each node.</p>
    pub security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Specifies the weekly time range during which maintenance on the DAX cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for <code>ddd</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>sun</code></p></li>
    /// <li>
    /// <p><code>mon</code></p></li>
    /// <li>
    /// <p><code>tue</code></p></li>
    /// <li>
    /// <p><code>wed</code></p></li>
    /// <li>
    /// <p><code>thu</code></p></li>
    /// <li>
    /// <p><code>fri</code></p></li>
    /// <li>
    /// <p><code>sat</code></p></li>
    /// </ul>
    /// <p>Example: <code>sun:05:00-sun:09:00</code></p><note>
    /// <p>If you don't specify a preferred maintenance window when you create or modify a cache cluster, DAX assigns a 60-minute maintenance window on a randomly selected day of the week.</p>
    /// </note>
    pub preferred_maintenance_window: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to which notifications will be sent.</p><note>
    /// <p>The Amazon SNS topic owner must be same as the DAX cluster owner.</p>
    /// </note>
    pub notification_topic_arn: ::std::option::Option<::std::string::String>,
    /// <p>A valid Amazon Resource Name (ARN) that identifies an IAM role. At runtime, DAX will assume this role and use the role's permissions to access DynamoDB on your behalf.</p>
    pub iam_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The parameter group to be associated with the DAX cluster.</p>
    pub parameter_group_name: ::std::option::Option<::std::string::String>,
    /// <p>A set of tags to associate with the DAX cluster.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>Represents the settings used to enable server-side encryption on the cluster.</p>
    pub sse_specification: ::std::option::Option<crate::types::SseSpecification>,
    /// <p>The type of encryption the cluster's endpoint should support. Values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code> for no encryption</p></li>
    /// <li>
    /// <p><code>TLS</code> for Transport Layer Security</p></li>
    /// </ul>
    pub cluster_endpoint_encryption_type: ::std::option::Option<crate::types::ClusterEndpointEncryptionType>,
}
impl CreateClusterInput {
    /// <p>The cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p><b>Constraints:</b></p>
    /// <ul>
    /// <li>
    /// <p>A name must contain from 1 to 20 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>A name cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
    /// <p>The compute and memory capacity of the nodes in the cluster.</p>
    pub fn node_type(&self) -> ::std::option::Option<&str> {
        self.node_type.as_deref()
    }
    /// <p>A description of the cluster.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The number of nodes in the DAX cluster. A replication factor of 1 will create a single-node cluster, without any read replicas. For additional fault tolerance, you can create a multiple node cluster with one or more read replicas. To do this, set <code>ReplicationFactor</code> to a number between 3 (one primary and two read replicas) and 10 (one primary and nine read replicas). <code>If the AvailabilityZones</code> parameter is provided, its length must equal the <code>ReplicationFactor</code>.</p><note>
    /// <p>AWS recommends that you have at least two read replicas per cluster.</p>
    /// </note>
    pub fn replication_factor(&self) -> ::std::option::Option<i32> {
        self.replication_factor
    }
    /// <p>The Availability Zones (AZs) in which the cluster nodes will reside after the cluster has been created or updated. If provided, the length of this list must equal the <code>ReplicationFactor</code> parameter. If you omit this parameter, DAX will spread the nodes across Availability Zones for the highest availability.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.availability_zones.is_none()`.
    pub fn availability_zones(&self) -> &[::std::string::String] {
        self.availability_zones.as_deref().unwrap_or_default()
    }
    /// <p>The name of the subnet group to be used for the replication group.</p><important>
    /// <p>DAX clusters can only run in an Amazon VPC environment. All of the subnets that you specify in a subnet group must exist in the same VPC.</p>
    /// </important>
    pub fn subnet_group_name(&self) -> ::std::option::Option<&str> {
        self.subnet_group_name.as_deref()
    }
    /// <p>A list of security group IDs to be assigned to each node in the DAX cluster. (Each of the security group ID is system-generated.)</p>
    /// <p>If this parameter is not specified, DAX assigns the default VPC security group to each node.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_ids.is_none()`.
    pub fn security_group_ids(&self) -> &[::std::string::String] {
        self.security_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the weekly time range during which maintenance on the DAX cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for <code>ddd</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>sun</code></p></li>
    /// <li>
    /// <p><code>mon</code></p></li>
    /// <li>
    /// <p><code>tue</code></p></li>
    /// <li>
    /// <p><code>wed</code></p></li>
    /// <li>
    /// <p><code>thu</code></p></li>
    /// <li>
    /// <p><code>fri</code></p></li>
    /// <li>
    /// <p><code>sat</code></p></li>
    /// </ul>
    /// <p>Example: <code>sun:05:00-sun:09:00</code></p><note>
    /// <p>If you don't specify a preferred maintenance window when you create or modify a cache cluster, DAX assigns a 60-minute maintenance window on a randomly selected day of the week.</p>
    /// </note>
    pub fn preferred_maintenance_window(&self) -> ::std::option::Option<&str> {
        self.preferred_maintenance_window.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to which notifications will be sent.</p><note>
    /// <p>The Amazon SNS topic owner must be same as the DAX cluster owner.</p>
    /// </note>
    pub fn notification_topic_arn(&self) -> ::std::option::Option<&str> {
        self.notification_topic_arn.as_deref()
    }
    /// <p>A valid Amazon Resource Name (ARN) that identifies an IAM role. At runtime, DAX will assume this role and use the role's permissions to access DynamoDB on your behalf.</p>
    pub fn iam_role_arn(&self) -> ::std::option::Option<&str> {
        self.iam_role_arn.as_deref()
    }
    /// <p>The parameter group to be associated with the DAX cluster.</p>
    pub fn parameter_group_name(&self) -> ::std::option::Option<&str> {
        self.parameter_group_name.as_deref()
    }
    /// <p>A set of tags to associate with the DAX cluster.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Represents the settings used to enable server-side encryption on the cluster.</p>
    pub fn sse_specification(&self) -> ::std::option::Option<&crate::types::SseSpecification> {
        self.sse_specification.as_ref()
    }
    /// <p>The type of encryption the cluster's endpoint should support. Values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code> for no encryption</p></li>
    /// <li>
    /// <p><code>TLS</code> for Transport Layer Security</p></li>
    /// </ul>
    pub fn cluster_endpoint_encryption_type(&self) -> ::std::option::Option<&crate::types::ClusterEndpointEncryptionType> {
        self.cluster_endpoint_encryption_type.as_ref()
    }
}
impl CreateClusterInput {
    /// Creates a new builder-style object to manufacture [`CreateClusterInput`](crate::operation::create_cluster::CreateClusterInput).
    pub fn builder() -> crate::operation::create_cluster::builders::CreateClusterInputBuilder {
        crate::operation::create_cluster::builders::CreateClusterInputBuilder::default()
    }
}

/// A builder for [`CreateClusterInput`](crate::operation::create_cluster::CreateClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateClusterInputBuilder {
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
    pub(crate) node_type: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) replication_factor: ::std::option::Option<i32>,
    pub(crate) availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) subnet_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) preferred_maintenance_window: ::std::option::Option<::std::string::String>,
    pub(crate) notification_topic_arn: ::std::option::Option<::std::string::String>,
    pub(crate) iam_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) sse_specification: ::std::option::Option<crate::types::SseSpecification>,
    pub(crate) cluster_endpoint_encryption_type: ::std::option::Option<crate::types::ClusterEndpointEncryptionType>,
}
impl CreateClusterInputBuilder {
    /// <p>The cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p><b>Constraints:</b></p>
    /// <ul>
    /// <li>
    /// <p>A name must contain from 1 to 20 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>A name cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// This field is required.
    pub fn cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p><b>Constraints:</b></p>
    /// <ul>
    /// <li>
    /// <p>A name must contain from 1 to 20 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>A name cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    pub fn set_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_name = input;
        self
    }
    /// <p>The cluster identifier. This parameter is stored as a lowercase string.</p>
    /// <p><b>Constraints:</b></p>
    /// <ul>
    /// <li>
    /// <p>A name must contain from 1 to 20 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>A name cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    pub fn get_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_name
    }
    /// <p>The compute and memory capacity of the nodes in the cluster.</p>
    /// This field is required.
    pub fn node_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The compute and memory capacity of the nodes in the cluster.</p>
    pub fn set_node_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node_type = input;
        self
    }
    /// <p>The compute and memory capacity of the nodes in the cluster.</p>
    pub fn get_node_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.node_type
    }
    /// <p>A description of the cluster.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the cluster.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the cluster.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The number of nodes in the DAX cluster. A replication factor of 1 will create a single-node cluster, without any read replicas. For additional fault tolerance, you can create a multiple node cluster with one or more read replicas. To do this, set <code>ReplicationFactor</code> to a number between 3 (one primary and two read replicas) and 10 (one primary and nine read replicas). <code>If the AvailabilityZones</code> parameter is provided, its length must equal the <code>ReplicationFactor</code>.</p><note>
    /// <p>AWS recommends that you have at least two read replicas per cluster.</p>
    /// </note>
    /// This field is required.
    pub fn replication_factor(mut self, input: i32) -> Self {
        self.replication_factor = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of nodes in the DAX cluster. A replication factor of 1 will create a single-node cluster, without any read replicas. For additional fault tolerance, you can create a multiple node cluster with one or more read replicas. To do this, set <code>ReplicationFactor</code> to a number between 3 (one primary and two read replicas) and 10 (one primary and nine read replicas). <code>If the AvailabilityZones</code> parameter is provided, its length must equal the <code>ReplicationFactor</code>.</p><note>
    /// <p>AWS recommends that you have at least two read replicas per cluster.</p>
    /// </note>
    pub fn set_replication_factor(mut self, input: ::std::option::Option<i32>) -> Self {
        self.replication_factor = input;
        self
    }
    /// <p>The number of nodes in the DAX cluster. A replication factor of 1 will create a single-node cluster, without any read replicas. For additional fault tolerance, you can create a multiple node cluster with one or more read replicas. To do this, set <code>ReplicationFactor</code> to a number between 3 (one primary and two read replicas) and 10 (one primary and nine read replicas). <code>If the AvailabilityZones</code> parameter is provided, its length must equal the <code>ReplicationFactor</code>.</p><note>
    /// <p>AWS recommends that you have at least two read replicas per cluster.</p>
    /// </note>
    pub fn get_replication_factor(&self) -> &::std::option::Option<i32> {
        &self.replication_factor
    }
    /// Appends an item to `availability_zones`.
    ///
    /// To override the contents of this collection use [`set_availability_zones`](Self::set_availability_zones).
    ///
    /// <p>The Availability Zones (AZs) in which the cluster nodes will reside after the cluster has been created or updated. If provided, the length of this list must equal the <code>ReplicationFactor</code> parameter. If you omit this parameter, DAX will spread the nodes across Availability Zones for the highest availability.</p>
    pub fn availability_zones(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.availability_zones.unwrap_or_default();
        v.push(input.into());
        self.availability_zones = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Availability Zones (AZs) in which the cluster nodes will reside after the cluster has been created or updated. If provided, the length of this list must equal the <code>ReplicationFactor</code> parameter. If you omit this parameter, DAX will spread the nodes across Availability Zones for the highest availability.</p>
    pub fn set_availability_zones(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.availability_zones = input;
        self
    }
    /// <p>The Availability Zones (AZs) in which the cluster nodes will reside after the cluster has been created or updated. If provided, the length of this list must equal the <code>ReplicationFactor</code> parameter. If you omit this parameter, DAX will spread the nodes across Availability Zones for the highest availability.</p>
    pub fn get_availability_zones(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.availability_zones
    }
    /// <p>The name of the subnet group to be used for the replication group.</p><important>
    /// <p>DAX clusters can only run in an Amazon VPC environment. All of the subnets that you specify in a subnet group must exist in the same VPC.</p>
    /// </important>
    pub fn subnet_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the subnet group to be used for the replication group.</p><important>
    /// <p>DAX clusters can only run in an Amazon VPC environment. All of the subnets that you specify in a subnet group must exist in the same VPC.</p>
    /// </important>
    pub fn set_subnet_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_group_name = input;
        self
    }
    /// <p>The name of the subnet group to be used for the replication group.</p><important>
    /// <p>DAX clusters can only run in an Amazon VPC environment. All of the subnets that you specify in a subnet group must exist in the same VPC.</p>
    /// </important>
    pub fn get_subnet_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_group_name
    }
    /// Appends an item to `security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_security_group_ids`](Self::set_security_group_ids).
    ///
    /// <p>A list of security group IDs to be assigned to each node in the DAX cluster. (Each of the security group ID is system-generated.)</p>
    /// <p>If this parameter is not specified, DAX assigns the default VPC security group to each node.</p>
    pub fn security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of security group IDs to be assigned to each node in the DAX cluster. (Each of the security group ID is system-generated.)</p>
    /// <p>If this parameter is not specified, DAX assigns the default VPC security group to each node.</p>
    pub fn set_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_group_ids = input;
        self
    }
    /// <p>A list of security group IDs to be assigned to each node in the DAX cluster. (Each of the security group ID is system-generated.)</p>
    /// <p>If this parameter is not specified, DAX assigns the default VPC security group to each node.</p>
    pub fn get_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_group_ids
    }
    /// <p>Specifies the weekly time range during which maintenance on the DAX cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for <code>ddd</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>sun</code></p></li>
    /// <li>
    /// <p><code>mon</code></p></li>
    /// <li>
    /// <p><code>tue</code></p></li>
    /// <li>
    /// <p><code>wed</code></p></li>
    /// <li>
    /// <p><code>thu</code></p></li>
    /// <li>
    /// <p><code>fri</code></p></li>
    /// <li>
    /// <p><code>sat</code></p></li>
    /// </ul>
    /// <p>Example: <code>sun:05:00-sun:09:00</code></p><note>
    /// <p>If you don't specify a preferred maintenance window when you create or modify a cache cluster, DAX assigns a 60-minute maintenance window on a randomly selected day of the week.</p>
    /// </note>
    pub fn preferred_maintenance_window(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.preferred_maintenance_window = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the weekly time range during which maintenance on the DAX cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for <code>ddd</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>sun</code></p></li>
    /// <li>
    /// <p><code>mon</code></p></li>
    /// <li>
    /// <p><code>tue</code></p></li>
    /// <li>
    /// <p><code>wed</code></p></li>
    /// <li>
    /// <p><code>thu</code></p></li>
    /// <li>
    /// <p><code>fri</code></p></li>
    /// <li>
    /// <p><code>sat</code></p></li>
    /// </ul>
    /// <p>Example: <code>sun:05:00-sun:09:00</code></p><note>
    /// <p>If you don't specify a preferred maintenance window when you create or modify a cache cluster, DAX assigns a 60-minute maintenance window on a randomly selected day of the week.</p>
    /// </note>
    pub fn set_preferred_maintenance_window(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.preferred_maintenance_window = input;
        self
    }
    /// <p>Specifies the weekly time range during which maintenance on the DAX cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for <code>ddd</code> are:</p>
    /// <ul>
    /// <li>
    /// <p><code>sun</code></p></li>
    /// <li>
    /// <p><code>mon</code></p></li>
    /// <li>
    /// <p><code>tue</code></p></li>
    /// <li>
    /// <p><code>wed</code></p></li>
    /// <li>
    /// <p><code>thu</code></p></li>
    /// <li>
    /// <p><code>fri</code></p></li>
    /// <li>
    /// <p><code>sat</code></p></li>
    /// </ul>
    /// <p>Example: <code>sun:05:00-sun:09:00</code></p><note>
    /// <p>If you don't specify a preferred maintenance window when you create or modify a cache cluster, DAX assigns a 60-minute maintenance window on a randomly selected day of the week.</p>
    /// </note>
    pub fn get_preferred_maintenance_window(&self) -> &::std::option::Option<::std::string::String> {
        &self.preferred_maintenance_window
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to which notifications will be sent.</p><note>
    /// <p>The Amazon SNS topic owner must be same as the DAX cluster owner.</p>
    /// </note>
    pub fn notification_topic_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notification_topic_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to which notifications will be sent.</p><note>
    /// <p>The Amazon SNS topic owner must be same as the DAX cluster owner.</p>
    /// </note>
    pub fn set_notification_topic_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notification_topic_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to which notifications will be sent.</p><note>
    /// <p>The Amazon SNS topic owner must be same as the DAX cluster owner.</p>
    /// </note>
    pub fn get_notification_topic_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.notification_topic_arn
    }
    /// <p>A valid Amazon Resource Name (ARN) that identifies an IAM role. At runtime, DAX will assume this role and use the role's permissions to access DynamoDB on your behalf.</p>
    /// This field is required.
    pub fn iam_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A valid Amazon Resource Name (ARN) that identifies an IAM role. At runtime, DAX will assume this role and use the role's permissions to access DynamoDB on your behalf.</p>
    pub fn set_iam_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role_arn = input;
        self
    }
    /// <p>A valid Amazon Resource Name (ARN) that identifies an IAM role. At runtime, DAX will assume this role and use the role's permissions to access DynamoDB on your behalf.</p>
    pub fn get_iam_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role_arn
    }
    /// <p>The parameter group to be associated with the DAX cluster.</p>
    pub fn parameter_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The parameter group to be associated with the DAX cluster.</p>
    pub fn set_parameter_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_group_name = input;
        self
    }
    /// <p>The parameter group to be associated with the DAX cluster.</p>
    pub fn get_parameter_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_group_name
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A set of tags to associate with the DAX cluster.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A set of tags to associate with the DAX cluster.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A set of tags to associate with the DAX cluster.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>Represents the settings used to enable server-side encryption on the cluster.</p>
    pub fn sse_specification(mut self, input: crate::types::SseSpecification) -> Self {
        self.sse_specification = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents the settings used to enable server-side encryption on the cluster.</p>
    pub fn set_sse_specification(mut self, input: ::std::option::Option<crate::types::SseSpecification>) -> Self {
        self.sse_specification = input;
        self
    }
    /// <p>Represents the settings used to enable server-side encryption on the cluster.</p>
    pub fn get_sse_specification(&self) -> &::std::option::Option<crate::types::SseSpecification> {
        &self.sse_specification
    }
    /// <p>The type of encryption the cluster's endpoint should support. Values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code> for no encryption</p></li>
    /// <li>
    /// <p><code>TLS</code> for Transport Layer Security</p></li>
    /// </ul>
    pub fn cluster_endpoint_encryption_type(mut self, input: crate::types::ClusterEndpointEncryptionType) -> Self {
        self.cluster_endpoint_encryption_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of encryption the cluster's endpoint should support. Values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code> for no encryption</p></li>
    /// <li>
    /// <p><code>TLS</code> for Transport Layer Security</p></li>
    /// </ul>
    pub fn set_cluster_endpoint_encryption_type(mut self, input: ::std::option::Option<crate::types::ClusterEndpointEncryptionType>) -> Self {
        self.cluster_endpoint_encryption_type = input;
        self
    }
    /// <p>The type of encryption the cluster's endpoint should support. Values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code> for no encryption</p></li>
    /// <li>
    /// <p><code>TLS</code> for Transport Layer Security</p></li>
    /// </ul>
    pub fn get_cluster_endpoint_encryption_type(&self) -> &::std::option::Option<crate::types::ClusterEndpointEncryptionType> {
        &self.cluster_endpoint_encryption_type
    }
    /// Consumes the builder and constructs a [`CreateClusterInput`](crate::operation::create_cluster::CreateClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_cluster::CreateClusterInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_cluster::CreateClusterInput {
            cluster_name: self.cluster_name,
            node_type: self.node_type,
            description: self.description,
            replication_factor: self.replication_factor,
            availability_zones: self.availability_zones,
            subnet_group_name: self.subnet_group_name,
            security_group_ids: self.security_group_ids,
            preferred_maintenance_window: self.preferred_maintenance_window,
            notification_topic_arn: self.notification_topic_arn,
            iam_role_arn: self.iam_role_arn,
            parameter_group_name: self.parameter_group_name,
            tags: self.tags,
            sse_specification: self.sse_specification,
            cluster_endpoint_encryption_type: self.cluster_endpoint_encryption_type,
        })
    }
}
