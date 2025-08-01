// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The desired instance type and desired number of replicas of each index partition.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScalingParameters {
    /// <p>The instance type that you want to preconfigure for your domain. For example, <code>search.m1.small</code>.</p>
    pub desired_instance_type: ::std::option::Option<crate::types::PartitionInstanceType>,
    /// <p>The number of replicas you want to preconfigure for each index partition.</p>
    pub desired_replication_count: i32,
    /// <p>The number of partitions you want to preconfigure for your domain. Only valid when you select <code>m2.2xlarge</code> as the desired instance type.</p>
    pub desired_partition_count: i32,
}
impl ScalingParameters {
    /// <p>The instance type that you want to preconfigure for your domain. For example, <code>search.m1.small</code>.</p>
    pub fn desired_instance_type(&self) -> ::std::option::Option<&crate::types::PartitionInstanceType> {
        self.desired_instance_type.as_ref()
    }
    /// <p>The number of replicas you want to preconfigure for each index partition.</p>
    pub fn desired_replication_count(&self) -> i32 {
        self.desired_replication_count
    }
    /// <p>The number of partitions you want to preconfigure for your domain. Only valid when you select <code>m2.2xlarge</code> as the desired instance type.</p>
    pub fn desired_partition_count(&self) -> i32 {
        self.desired_partition_count
    }
}
impl ScalingParameters {
    /// Creates a new builder-style object to manufacture [`ScalingParameters`](crate::types::ScalingParameters).
    pub fn builder() -> crate::types::builders::ScalingParametersBuilder {
        crate::types::builders::ScalingParametersBuilder::default()
    }
}

/// A builder for [`ScalingParameters`](crate::types::ScalingParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScalingParametersBuilder {
    pub(crate) desired_instance_type: ::std::option::Option<crate::types::PartitionInstanceType>,
    pub(crate) desired_replication_count: ::std::option::Option<i32>,
    pub(crate) desired_partition_count: ::std::option::Option<i32>,
}
impl ScalingParametersBuilder {
    /// <p>The instance type that you want to preconfigure for your domain. For example, <code>search.m1.small</code>.</p>
    pub fn desired_instance_type(mut self, input: crate::types::PartitionInstanceType) -> Self {
        self.desired_instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The instance type that you want to preconfigure for your domain. For example, <code>search.m1.small</code>.</p>
    pub fn set_desired_instance_type(mut self, input: ::std::option::Option<crate::types::PartitionInstanceType>) -> Self {
        self.desired_instance_type = input;
        self
    }
    /// <p>The instance type that you want to preconfigure for your domain. For example, <code>search.m1.small</code>.</p>
    pub fn get_desired_instance_type(&self) -> &::std::option::Option<crate::types::PartitionInstanceType> {
        &self.desired_instance_type
    }
    /// <p>The number of replicas you want to preconfigure for each index partition.</p>
    pub fn desired_replication_count(mut self, input: i32) -> Self {
        self.desired_replication_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of replicas you want to preconfigure for each index partition.</p>
    pub fn set_desired_replication_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.desired_replication_count = input;
        self
    }
    /// <p>The number of replicas you want to preconfigure for each index partition.</p>
    pub fn get_desired_replication_count(&self) -> &::std::option::Option<i32> {
        &self.desired_replication_count
    }
    /// <p>The number of partitions you want to preconfigure for your domain. Only valid when you select <code>m2.2xlarge</code> as the desired instance type.</p>
    pub fn desired_partition_count(mut self, input: i32) -> Self {
        self.desired_partition_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of partitions you want to preconfigure for your domain. Only valid when you select <code>m2.2xlarge</code> as the desired instance type.</p>
    pub fn set_desired_partition_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.desired_partition_count = input;
        self
    }
    /// <p>The number of partitions you want to preconfigure for your domain. Only valid when you select <code>m2.2xlarge</code> as the desired instance type.</p>
    pub fn get_desired_partition_count(&self) -> &::std::option::Option<i32> {
        &self.desired_partition_count
    }
    /// Consumes the builder and constructs a [`ScalingParameters`](crate::types::ScalingParameters).
    pub fn build(self) -> crate::types::ScalingParameters {
        crate::types::ScalingParameters {
            desired_instance_type: self.desired_instance_type,
            desired_replication_count: self.desired_replication_count.unwrap_or_default(),
            desired_partition_count: self.desired_partition_count.unwrap_or_default(),
        }
    }
}
