// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a scalable resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScalingPlanResource {
    /// <p>The name of the scaling plan.</p>
    pub scaling_plan_name: ::std::string::String,
    /// <p>The version number of the scaling plan.</p>
    pub scaling_plan_version: i64,
    /// <p>The namespace of the AWS service.</p>
    pub service_namespace: crate::types::ServiceNamespace,
    /// <p>The ID of the resource. This string consists of the resource type and unique identifier.</p>
    /// <ul>
    /// <li>
    /// <p>Auto Scaling group - The resource type is <code>autoScalingGroup</code> and the unique identifier is the name of the Auto Scaling group. Example: <code>autoScalingGroup/my-asg</code>.</p></li>
    /// <li>
    /// <p>ECS service - The resource type is <code>service</code> and the unique identifier is the cluster name and service name. Example: <code>service/default/sample-webapp</code>.</p></li>
    /// <li>
    /// <p>Spot Fleet request - The resource type is <code>spot-fleet-request</code> and the unique identifier is the Spot Fleet request ID. Example: <code>spot-fleet-request/sfr-73fbd2ce-aa30-494c-8788-1cee4EXAMPLE</code>.</p></li>
    /// <li>
    /// <p>DynamoDB table - The resource type is <code>table</code> and the unique identifier is the resource ID. Example: <code>table/my-table</code>.</p></li>
    /// <li>
    /// <p>DynamoDB global secondary index - The resource type is <code>index</code> and the unique identifier is the resource ID. Example: <code>table/my-table/index/my-table-index</code>.</p></li>
    /// <li>
    /// <p>Aurora DB cluster - The resource type is <code>cluster</code> and the unique identifier is the cluster name. Example: <code>cluster:my-db-cluster</code>.</p></li>
    /// </ul>
    pub resource_id: ::std::string::String,
    /// <p>The scalable dimension for the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>autoscaling:autoScalingGroup:DesiredCapacity</code> - The desired capacity of an Auto Scaling group.</p></li>
    /// <li>
    /// <p><code>ecs:service:DesiredCount</code> - The desired task count of an ECS service.</p></li>
    /// <li>
    /// <p><code>ec2:spot-fleet-request:TargetCapacity</code> - The target capacity of a Spot Fleet request.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>rds:cluster:ReadReplicaCount</code> - The count of Aurora Replicas in an Aurora DB cluster. Available for Aurora MySQL-compatible edition and Aurora PostgreSQL-compatible edition.</p></li>
    /// </ul>
    pub scalable_dimension: crate::types::ScalableDimension,
    /// <p>The scaling policies.</p>
    pub scaling_policies: ::std::option::Option<::std::vec::Vec<crate::types::ScalingPolicy>>,
    /// <p>The scaling status of the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>Active</code> - The scaling configuration is active.</p></li>
    /// <li>
    /// <p><code>Inactive</code> - The scaling configuration is not active because the scaling plan is being created or the scaling configuration could not be applied. Check the status message for more information.</p></li>
    /// <li>
    /// <p><code>PartiallyActive</code> - The scaling configuration is partially active because the scaling plan is being created or deleted or the scaling configuration could not be fully applied. Check the status message for more information.</p></li>
    /// </ul>
    pub scaling_status_code: crate::types::ScalingStatusCode,
    /// <p>A simple message about the current scaling status of the resource.</p>
    pub scaling_status_message: ::std::option::Option<::std::string::String>,
}
impl ScalingPlanResource {
    /// <p>The name of the scaling plan.</p>
    pub fn scaling_plan_name(&self) -> &str {
        use std::ops::Deref;
        self.scaling_plan_name.deref()
    }
    /// <p>The version number of the scaling plan.</p>
    pub fn scaling_plan_version(&self) -> i64 {
        self.scaling_plan_version
    }
    /// <p>The namespace of the AWS service.</p>
    pub fn service_namespace(&self) -> &crate::types::ServiceNamespace {
        &self.service_namespace
    }
    /// <p>The ID of the resource. This string consists of the resource type and unique identifier.</p>
    /// <ul>
    /// <li>
    /// <p>Auto Scaling group - The resource type is <code>autoScalingGroup</code> and the unique identifier is the name of the Auto Scaling group. Example: <code>autoScalingGroup/my-asg</code>.</p></li>
    /// <li>
    /// <p>ECS service - The resource type is <code>service</code> and the unique identifier is the cluster name and service name. Example: <code>service/default/sample-webapp</code>.</p></li>
    /// <li>
    /// <p>Spot Fleet request - The resource type is <code>spot-fleet-request</code> and the unique identifier is the Spot Fleet request ID. Example: <code>spot-fleet-request/sfr-73fbd2ce-aa30-494c-8788-1cee4EXAMPLE</code>.</p></li>
    /// <li>
    /// <p>DynamoDB table - The resource type is <code>table</code> and the unique identifier is the resource ID. Example: <code>table/my-table</code>.</p></li>
    /// <li>
    /// <p>DynamoDB global secondary index - The resource type is <code>index</code> and the unique identifier is the resource ID. Example: <code>table/my-table/index/my-table-index</code>.</p></li>
    /// <li>
    /// <p>Aurora DB cluster - The resource type is <code>cluster</code> and the unique identifier is the cluster name. Example: <code>cluster:my-db-cluster</code>.</p></li>
    /// </ul>
    pub fn resource_id(&self) -> &str {
        use std::ops::Deref;
        self.resource_id.deref()
    }
    /// <p>The scalable dimension for the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>autoscaling:autoScalingGroup:DesiredCapacity</code> - The desired capacity of an Auto Scaling group.</p></li>
    /// <li>
    /// <p><code>ecs:service:DesiredCount</code> - The desired task count of an ECS service.</p></li>
    /// <li>
    /// <p><code>ec2:spot-fleet-request:TargetCapacity</code> - The target capacity of a Spot Fleet request.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>rds:cluster:ReadReplicaCount</code> - The count of Aurora Replicas in an Aurora DB cluster. Available for Aurora MySQL-compatible edition and Aurora PostgreSQL-compatible edition.</p></li>
    /// </ul>
    pub fn scalable_dimension(&self) -> &crate::types::ScalableDimension {
        &self.scalable_dimension
    }
    /// <p>The scaling policies.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.scaling_policies.is_none()`.
    pub fn scaling_policies(&self) -> &[crate::types::ScalingPolicy] {
        self.scaling_policies.as_deref().unwrap_or_default()
    }
    /// <p>The scaling status of the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>Active</code> - The scaling configuration is active.</p></li>
    /// <li>
    /// <p><code>Inactive</code> - The scaling configuration is not active because the scaling plan is being created or the scaling configuration could not be applied. Check the status message for more information.</p></li>
    /// <li>
    /// <p><code>PartiallyActive</code> - The scaling configuration is partially active because the scaling plan is being created or deleted or the scaling configuration could not be fully applied. Check the status message for more information.</p></li>
    /// </ul>
    pub fn scaling_status_code(&self) -> &crate::types::ScalingStatusCode {
        &self.scaling_status_code
    }
    /// <p>A simple message about the current scaling status of the resource.</p>
    pub fn scaling_status_message(&self) -> ::std::option::Option<&str> {
        self.scaling_status_message.as_deref()
    }
}
impl ScalingPlanResource {
    /// Creates a new builder-style object to manufacture [`ScalingPlanResource`](crate::types::ScalingPlanResource).
    pub fn builder() -> crate::types::builders::ScalingPlanResourceBuilder {
        crate::types::builders::ScalingPlanResourceBuilder::default()
    }
}

/// A builder for [`ScalingPlanResource`](crate::types::ScalingPlanResource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScalingPlanResourceBuilder {
    pub(crate) scaling_plan_name: ::std::option::Option<::std::string::String>,
    pub(crate) scaling_plan_version: ::std::option::Option<i64>,
    pub(crate) service_namespace: ::std::option::Option<crate::types::ServiceNamespace>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) scalable_dimension: ::std::option::Option<crate::types::ScalableDimension>,
    pub(crate) scaling_policies: ::std::option::Option<::std::vec::Vec<crate::types::ScalingPolicy>>,
    pub(crate) scaling_status_code: ::std::option::Option<crate::types::ScalingStatusCode>,
    pub(crate) scaling_status_message: ::std::option::Option<::std::string::String>,
}
impl ScalingPlanResourceBuilder {
    /// <p>The name of the scaling plan.</p>
    /// This field is required.
    pub fn scaling_plan_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scaling_plan_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the scaling plan.</p>
    pub fn set_scaling_plan_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scaling_plan_name = input;
        self
    }
    /// <p>The name of the scaling plan.</p>
    pub fn get_scaling_plan_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.scaling_plan_name
    }
    /// <p>The version number of the scaling plan.</p>
    /// This field is required.
    pub fn scaling_plan_version(mut self, input: i64) -> Self {
        self.scaling_plan_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number of the scaling plan.</p>
    pub fn set_scaling_plan_version(mut self, input: ::std::option::Option<i64>) -> Self {
        self.scaling_plan_version = input;
        self
    }
    /// <p>The version number of the scaling plan.</p>
    pub fn get_scaling_plan_version(&self) -> &::std::option::Option<i64> {
        &self.scaling_plan_version
    }
    /// <p>The namespace of the AWS service.</p>
    /// This field is required.
    pub fn service_namespace(mut self, input: crate::types::ServiceNamespace) -> Self {
        self.service_namespace = ::std::option::Option::Some(input);
        self
    }
    /// <p>The namespace of the AWS service.</p>
    pub fn set_service_namespace(mut self, input: ::std::option::Option<crate::types::ServiceNamespace>) -> Self {
        self.service_namespace = input;
        self
    }
    /// <p>The namespace of the AWS service.</p>
    pub fn get_service_namespace(&self) -> &::std::option::Option<crate::types::ServiceNamespace> {
        &self.service_namespace
    }
    /// <p>The ID of the resource. This string consists of the resource type and unique identifier.</p>
    /// <ul>
    /// <li>
    /// <p>Auto Scaling group - The resource type is <code>autoScalingGroup</code> and the unique identifier is the name of the Auto Scaling group. Example: <code>autoScalingGroup/my-asg</code>.</p></li>
    /// <li>
    /// <p>ECS service - The resource type is <code>service</code> and the unique identifier is the cluster name and service name. Example: <code>service/default/sample-webapp</code>.</p></li>
    /// <li>
    /// <p>Spot Fleet request - The resource type is <code>spot-fleet-request</code> and the unique identifier is the Spot Fleet request ID. Example: <code>spot-fleet-request/sfr-73fbd2ce-aa30-494c-8788-1cee4EXAMPLE</code>.</p></li>
    /// <li>
    /// <p>DynamoDB table - The resource type is <code>table</code> and the unique identifier is the resource ID. Example: <code>table/my-table</code>.</p></li>
    /// <li>
    /// <p>DynamoDB global secondary index - The resource type is <code>index</code> and the unique identifier is the resource ID. Example: <code>table/my-table/index/my-table-index</code>.</p></li>
    /// <li>
    /// <p>Aurora DB cluster - The resource type is <code>cluster</code> and the unique identifier is the cluster name. Example: <code>cluster:my-db-cluster</code>.</p></li>
    /// </ul>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource. This string consists of the resource type and unique identifier.</p>
    /// <ul>
    /// <li>
    /// <p>Auto Scaling group - The resource type is <code>autoScalingGroup</code> and the unique identifier is the name of the Auto Scaling group. Example: <code>autoScalingGroup/my-asg</code>.</p></li>
    /// <li>
    /// <p>ECS service - The resource type is <code>service</code> and the unique identifier is the cluster name and service name. Example: <code>service/default/sample-webapp</code>.</p></li>
    /// <li>
    /// <p>Spot Fleet request - The resource type is <code>spot-fleet-request</code> and the unique identifier is the Spot Fleet request ID. Example: <code>spot-fleet-request/sfr-73fbd2ce-aa30-494c-8788-1cee4EXAMPLE</code>.</p></li>
    /// <li>
    /// <p>DynamoDB table - The resource type is <code>table</code> and the unique identifier is the resource ID. Example: <code>table/my-table</code>.</p></li>
    /// <li>
    /// <p>DynamoDB global secondary index - The resource type is <code>index</code> and the unique identifier is the resource ID. Example: <code>table/my-table/index/my-table-index</code>.</p></li>
    /// <li>
    /// <p>Aurora DB cluster - The resource type is <code>cluster</code> and the unique identifier is the cluster name. Example: <code>cluster:my-db-cluster</code>.</p></li>
    /// </ul>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The ID of the resource. This string consists of the resource type and unique identifier.</p>
    /// <ul>
    /// <li>
    /// <p>Auto Scaling group - The resource type is <code>autoScalingGroup</code> and the unique identifier is the name of the Auto Scaling group. Example: <code>autoScalingGroup/my-asg</code>.</p></li>
    /// <li>
    /// <p>ECS service - The resource type is <code>service</code> and the unique identifier is the cluster name and service name. Example: <code>service/default/sample-webapp</code>.</p></li>
    /// <li>
    /// <p>Spot Fleet request - The resource type is <code>spot-fleet-request</code> and the unique identifier is the Spot Fleet request ID. Example: <code>spot-fleet-request/sfr-73fbd2ce-aa30-494c-8788-1cee4EXAMPLE</code>.</p></li>
    /// <li>
    /// <p>DynamoDB table - The resource type is <code>table</code> and the unique identifier is the resource ID. Example: <code>table/my-table</code>.</p></li>
    /// <li>
    /// <p>DynamoDB global secondary index - The resource type is <code>index</code> and the unique identifier is the resource ID. Example: <code>table/my-table/index/my-table-index</code>.</p></li>
    /// <li>
    /// <p>Aurora DB cluster - The resource type is <code>cluster</code> and the unique identifier is the cluster name. Example: <code>cluster:my-db-cluster</code>.</p></li>
    /// </ul>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The scalable dimension for the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>autoscaling:autoScalingGroup:DesiredCapacity</code> - The desired capacity of an Auto Scaling group.</p></li>
    /// <li>
    /// <p><code>ecs:service:DesiredCount</code> - The desired task count of an ECS service.</p></li>
    /// <li>
    /// <p><code>ec2:spot-fleet-request:TargetCapacity</code> - The target capacity of a Spot Fleet request.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>rds:cluster:ReadReplicaCount</code> - The count of Aurora Replicas in an Aurora DB cluster. Available for Aurora MySQL-compatible edition and Aurora PostgreSQL-compatible edition.</p></li>
    /// </ul>
    /// This field is required.
    pub fn scalable_dimension(mut self, input: crate::types::ScalableDimension) -> Self {
        self.scalable_dimension = ::std::option::Option::Some(input);
        self
    }
    /// <p>The scalable dimension for the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>autoscaling:autoScalingGroup:DesiredCapacity</code> - The desired capacity of an Auto Scaling group.</p></li>
    /// <li>
    /// <p><code>ecs:service:DesiredCount</code> - The desired task count of an ECS service.</p></li>
    /// <li>
    /// <p><code>ec2:spot-fleet-request:TargetCapacity</code> - The target capacity of a Spot Fleet request.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>rds:cluster:ReadReplicaCount</code> - The count of Aurora Replicas in an Aurora DB cluster. Available for Aurora MySQL-compatible edition and Aurora PostgreSQL-compatible edition.</p></li>
    /// </ul>
    pub fn set_scalable_dimension(mut self, input: ::std::option::Option<crate::types::ScalableDimension>) -> Self {
        self.scalable_dimension = input;
        self
    }
    /// <p>The scalable dimension for the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>autoscaling:autoScalingGroup:DesiredCapacity</code> - The desired capacity of an Auto Scaling group.</p></li>
    /// <li>
    /// <p><code>ecs:service:DesiredCount</code> - The desired task count of an ECS service.</p></li>
    /// <li>
    /// <p><code>ec2:spot-fleet-request:TargetCapacity</code> - The target capacity of a Spot Fleet request.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:table:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB table.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:ReadCapacityUnits</code> - The provisioned read capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>dynamodb:index:WriteCapacityUnits</code> - The provisioned write capacity for a DynamoDB global secondary index.</p></li>
    /// <li>
    /// <p><code>rds:cluster:ReadReplicaCount</code> - The count of Aurora Replicas in an Aurora DB cluster. Available for Aurora MySQL-compatible edition and Aurora PostgreSQL-compatible edition.</p></li>
    /// </ul>
    pub fn get_scalable_dimension(&self) -> &::std::option::Option<crate::types::ScalableDimension> {
        &self.scalable_dimension
    }
    /// Appends an item to `scaling_policies`.
    ///
    /// To override the contents of this collection use [`set_scaling_policies`](Self::set_scaling_policies).
    ///
    /// <p>The scaling policies.</p>
    pub fn scaling_policies(mut self, input: crate::types::ScalingPolicy) -> Self {
        let mut v = self.scaling_policies.unwrap_or_default();
        v.push(input);
        self.scaling_policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>The scaling policies.</p>
    pub fn set_scaling_policies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ScalingPolicy>>) -> Self {
        self.scaling_policies = input;
        self
    }
    /// <p>The scaling policies.</p>
    pub fn get_scaling_policies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ScalingPolicy>> {
        &self.scaling_policies
    }
    /// <p>The scaling status of the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>Active</code> - The scaling configuration is active.</p></li>
    /// <li>
    /// <p><code>Inactive</code> - The scaling configuration is not active because the scaling plan is being created or the scaling configuration could not be applied. Check the status message for more information.</p></li>
    /// <li>
    /// <p><code>PartiallyActive</code> - The scaling configuration is partially active because the scaling plan is being created or deleted or the scaling configuration could not be fully applied. Check the status message for more information.</p></li>
    /// </ul>
    /// This field is required.
    pub fn scaling_status_code(mut self, input: crate::types::ScalingStatusCode) -> Self {
        self.scaling_status_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The scaling status of the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>Active</code> - The scaling configuration is active.</p></li>
    /// <li>
    /// <p><code>Inactive</code> - The scaling configuration is not active because the scaling plan is being created or the scaling configuration could not be applied. Check the status message for more information.</p></li>
    /// <li>
    /// <p><code>PartiallyActive</code> - The scaling configuration is partially active because the scaling plan is being created or deleted or the scaling configuration could not be fully applied. Check the status message for more information.</p></li>
    /// </ul>
    pub fn set_scaling_status_code(mut self, input: ::std::option::Option<crate::types::ScalingStatusCode>) -> Self {
        self.scaling_status_code = input;
        self
    }
    /// <p>The scaling status of the resource.</p>
    /// <ul>
    /// <li>
    /// <p><code>Active</code> - The scaling configuration is active.</p></li>
    /// <li>
    /// <p><code>Inactive</code> - The scaling configuration is not active because the scaling plan is being created or the scaling configuration could not be applied. Check the status message for more information.</p></li>
    /// <li>
    /// <p><code>PartiallyActive</code> - The scaling configuration is partially active because the scaling plan is being created or deleted or the scaling configuration could not be fully applied. Check the status message for more information.</p></li>
    /// </ul>
    pub fn get_scaling_status_code(&self) -> &::std::option::Option<crate::types::ScalingStatusCode> {
        &self.scaling_status_code
    }
    /// <p>A simple message about the current scaling status of the resource.</p>
    pub fn scaling_status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scaling_status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A simple message about the current scaling status of the resource.</p>
    pub fn set_scaling_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scaling_status_message = input;
        self
    }
    /// <p>A simple message about the current scaling status of the resource.</p>
    pub fn get_scaling_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.scaling_status_message
    }
    /// Consumes the builder and constructs a [`ScalingPlanResource`](crate::types::ScalingPlanResource).
    /// This method will fail if any of the following fields are not set:
    /// - [`scaling_plan_name`](crate::types::builders::ScalingPlanResourceBuilder::scaling_plan_name)
    /// - [`scaling_plan_version`](crate::types::builders::ScalingPlanResourceBuilder::scaling_plan_version)
    /// - [`service_namespace`](crate::types::builders::ScalingPlanResourceBuilder::service_namespace)
    /// - [`resource_id`](crate::types::builders::ScalingPlanResourceBuilder::resource_id)
    /// - [`scalable_dimension`](crate::types::builders::ScalingPlanResourceBuilder::scalable_dimension)
    /// - [`scaling_status_code`](crate::types::builders::ScalingPlanResourceBuilder::scaling_status_code)
    pub fn build(self) -> ::std::result::Result<crate::types::ScalingPlanResource, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ScalingPlanResource {
            scaling_plan_name: self.scaling_plan_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scaling_plan_name",
                    "scaling_plan_name was not specified but it is required when building ScalingPlanResource",
                )
            })?,
            scaling_plan_version: self.scaling_plan_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scaling_plan_version",
                    "scaling_plan_version was not specified but it is required when building ScalingPlanResource",
                )
            })?,
            service_namespace: self.service_namespace.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "service_namespace",
                    "service_namespace was not specified but it is required when building ScalingPlanResource",
                )
            })?,
            resource_id: self.resource_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_id",
                    "resource_id was not specified but it is required when building ScalingPlanResource",
                )
            })?,
            scalable_dimension: self.scalable_dimension.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scalable_dimension",
                    "scalable_dimension was not specified but it is required when building ScalingPlanResource",
                )
            })?,
            scaling_policies: self.scaling_policies,
            scaling_status_code: self.scaling_status_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scaling_status_code",
                    "scaling_status_code was not specified but it is required when building ScalingPlanResource",
                )
            })?,
            scaling_status_message: self.scaling_status_message,
        })
    }
}
