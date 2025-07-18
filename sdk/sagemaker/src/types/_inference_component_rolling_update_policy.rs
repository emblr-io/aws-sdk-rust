// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a rolling deployment strategy for updating a SageMaker AI inference component.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InferenceComponentRollingUpdatePolicy {
    /// <p>The batch size for each rolling step in the deployment process. For each step, SageMaker AI provisions capacity on the new endpoint fleet, routes traffic to that fleet, and terminates capacity on the old endpoint fleet. The value must be between 5% to 50% of the copy count of the inference component.</p>
    pub maximum_batch_size: ::std::option::Option<crate::types::InferenceComponentCapacitySize>,
    /// <p>The length of the baking period, during which SageMaker AI monitors alarms for each batch on the new fleet.</p>
    pub wait_interval_in_seconds: ::std::option::Option<i32>,
    /// <p>The time limit for the total deployment. Exceeding this limit causes a timeout.</p>
    pub maximum_execution_timeout_in_seconds: ::std::option::Option<i32>,
    /// <p>The batch size for a rollback to the old endpoint fleet. If this field is absent, the value is set to the default, which is 100% of the total capacity. When the default is used, SageMaker AI provisions the entire capacity of the old fleet at once during rollback.</p>
    pub rollback_maximum_batch_size: ::std::option::Option<crate::types::InferenceComponentCapacitySize>,
}
impl InferenceComponentRollingUpdatePolicy {
    /// <p>The batch size for each rolling step in the deployment process. For each step, SageMaker AI provisions capacity on the new endpoint fleet, routes traffic to that fleet, and terminates capacity on the old endpoint fleet. The value must be between 5% to 50% of the copy count of the inference component.</p>
    pub fn maximum_batch_size(&self) -> ::std::option::Option<&crate::types::InferenceComponentCapacitySize> {
        self.maximum_batch_size.as_ref()
    }
    /// <p>The length of the baking period, during which SageMaker AI monitors alarms for each batch on the new fleet.</p>
    pub fn wait_interval_in_seconds(&self) -> ::std::option::Option<i32> {
        self.wait_interval_in_seconds
    }
    /// <p>The time limit for the total deployment. Exceeding this limit causes a timeout.</p>
    pub fn maximum_execution_timeout_in_seconds(&self) -> ::std::option::Option<i32> {
        self.maximum_execution_timeout_in_seconds
    }
    /// <p>The batch size for a rollback to the old endpoint fleet. If this field is absent, the value is set to the default, which is 100% of the total capacity. When the default is used, SageMaker AI provisions the entire capacity of the old fleet at once during rollback.</p>
    pub fn rollback_maximum_batch_size(&self) -> ::std::option::Option<&crate::types::InferenceComponentCapacitySize> {
        self.rollback_maximum_batch_size.as_ref()
    }
}
impl InferenceComponentRollingUpdatePolicy {
    /// Creates a new builder-style object to manufacture [`InferenceComponentRollingUpdatePolicy`](crate::types::InferenceComponentRollingUpdatePolicy).
    pub fn builder() -> crate::types::builders::InferenceComponentRollingUpdatePolicyBuilder {
        crate::types::builders::InferenceComponentRollingUpdatePolicyBuilder::default()
    }
}

/// A builder for [`InferenceComponentRollingUpdatePolicy`](crate::types::InferenceComponentRollingUpdatePolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InferenceComponentRollingUpdatePolicyBuilder {
    pub(crate) maximum_batch_size: ::std::option::Option<crate::types::InferenceComponentCapacitySize>,
    pub(crate) wait_interval_in_seconds: ::std::option::Option<i32>,
    pub(crate) maximum_execution_timeout_in_seconds: ::std::option::Option<i32>,
    pub(crate) rollback_maximum_batch_size: ::std::option::Option<crate::types::InferenceComponentCapacitySize>,
}
impl InferenceComponentRollingUpdatePolicyBuilder {
    /// <p>The batch size for each rolling step in the deployment process. For each step, SageMaker AI provisions capacity on the new endpoint fleet, routes traffic to that fleet, and terminates capacity on the old endpoint fleet. The value must be between 5% to 50% of the copy count of the inference component.</p>
    /// This field is required.
    pub fn maximum_batch_size(mut self, input: crate::types::InferenceComponentCapacitySize) -> Self {
        self.maximum_batch_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The batch size for each rolling step in the deployment process. For each step, SageMaker AI provisions capacity on the new endpoint fleet, routes traffic to that fleet, and terminates capacity on the old endpoint fleet. The value must be between 5% to 50% of the copy count of the inference component.</p>
    pub fn set_maximum_batch_size(mut self, input: ::std::option::Option<crate::types::InferenceComponentCapacitySize>) -> Self {
        self.maximum_batch_size = input;
        self
    }
    /// <p>The batch size for each rolling step in the deployment process. For each step, SageMaker AI provisions capacity on the new endpoint fleet, routes traffic to that fleet, and terminates capacity on the old endpoint fleet. The value must be between 5% to 50% of the copy count of the inference component.</p>
    pub fn get_maximum_batch_size(&self) -> &::std::option::Option<crate::types::InferenceComponentCapacitySize> {
        &self.maximum_batch_size
    }
    /// <p>The length of the baking period, during which SageMaker AI monitors alarms for each batch on the new fleet.</p>
    /// This field is required.
    pub fn wait_interval_in_seconds(mut self, input: i32) -> Self {
        self.wait_interval_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The length of the baking period, during which SageMaker AI monitors alarms for each batch on the new fleet.</p>
    pub fn set_wait_interval_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.wait_interval_in_seconds = input;
        self
    }
    /// <p>The length of the baking period, during which SageMaker AI monitors alarms for each batch on the new fleet.</p>
    pub fn get_wait_interval_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.wait_interval_in_seconds
    }
    /// <p>The time limit for the total deployment. Exceeding this limit causes a timeout.</p>
    pub fn maximum_execution_timeout_in_seconds(mut self, input: i32) -> Self {
        self.maximum_execution_timeout_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time limit for the total deployment. Exceeding this limit causes a timeout.</p>
    pub fn set_maximum_execution_timeout_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_execution_timeout_in_seconds = input;
        self
    }
    /// <p>The time limit for the total deployment. Exceeding this limit causes a timeout.</p>
    pub fn get_maximum_execution_timeout_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.maximum_execution_timeout_in_seconds
    }
    /// <p>The batch size for a rollback to the old endpoint fleet. If this field is absent, the value is set to the default, which is 100% of the total capacity. When the default is used, SageMaker AI provisions the entire capacity of the old fleet at once during rollback.</p>
    pub fn rollback_maximum_batch_size(mut self, input: crate::types::InferenceComponentCapacitySize) -> Self {
        self.rollback_maximum_batch_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The batch size for a rollback to the old endpoint fleet. If this field is absent, the value is set to the default, which is 100% of the total capacity. When the default is used, SageMaker AI provisions the entire capacity of the old fleet at once during rollback.</p>
    pub fn set_rollback_maximum_batch_size(mut self, input: ::std::option::Option<crate::types::InferenceComponentCapacitySize>) -> Self {
        self.rollback_maximum_batch_size = input;
        self
    }
    /// <p>The batch size for a rollback to the old endpoint fleet. If this field is absent, the value is set to the default, which is 100% of the total capacity. When the default is used, SageMaker AI provisions the entire capacity of the old fleet at once during rollback.</p>
    pub fn get_rollback_maximum_batch_size(&self) -> &::std::option::Option<crate::types::InferenceComponentCapacitySize> {
        &self.rollback_maximum_batch_size
    }
    /// Consumes the builder and constructs a [`InferenceComponentRollingUpdatePolicy`](crate::types::InferenceComponentRollingUpdatePolicy).
    pub fn build(self) -> crate::types::InferenceComponentRollingUpdatePolicy {
        crate::types::InferenceComponentRollingUpdatePolicy {
            maximum_batch_size: self.maximum_batch_size,
            wait_interval_in_seconds: self.wait_interval_in_seconds,
            maximum_execution_timeout_in_seconds: self.maximum_execution_timeout_in_seconds,
            rollback_maximum_batch_size: self.rollback_maximum_batch_size,
        }
    }
}
