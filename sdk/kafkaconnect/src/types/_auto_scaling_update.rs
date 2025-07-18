// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The updates to the auto scaling parameters for the connector.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoScalingUpdate {
    /// <p>The target maximum number of workers allocated to the connector.</p>
    pub max_worker_count: i32,
    /// <p>The target number of microcontroller units (MCUs) allocated to each connector worker. The valid values are 1,2,4,8.</p>
    pub mcu_count: i32,
    /// <p>The target minimum number of workers allocated to the connector.</p>
    pub min_worker_count: i32,
    /// <p>The target sacle-in policy for the connector.</p>
    pub scale_in_policy: ::std::option::Option<crate::types::ScaleInPolicyUpdate>,
    /// <p>The target sacle-out policy for the connector.</p>
    pub scale_out_policy: ::std::option::Option<crate::types::ScaleOutPolicyUpdate>,
}
impl AutoScalingUpdate {
    /// <p>The target maximum number of workers allocated to the connector.</p>
    pub fn max_worker_count(&self) -> i32 {
        self.max_worker_count
    }
    /// <p>The target number of microcontroller units (MCUs) allocated to each connector worker. The valid values are 1,2,4,8.</p>
    pub fn mcu_count(&self) -> i32 {
        self.mcu_count
    }
    /// <p>The target minimum number of workers allocated to the connector.</p>
    pub fn min_worker_count(&self) -> i32 {
        self.min_worker_count
    }
    /// <p>The target sacle-in policy for the connector.</p>
    pub fn scale_in_policy(&self) -> ::std::option::Option<&crate::types::ScaleInPolicyUpdate> {
        self.scale_in_policy.as_ref()
    }
    /// <p>The target sacle-out policy for the connector.</p>
    pub fn scale_out_policy(&self) -> ::std::option::Option<&crate::types::ScaleOutPolicyUpdate> {
        self.scale_out_policy.as_ref()
    }
}
impl AutoScalingUpdate {
    /// Creates a new builder-style object to manufacture [`AutoScalingUpdate`](crate::types::AutoScalingUpdate).
    pub fn builder() -> crate::types::builders::AutoScalingUpdateBuilder {
        crate::types::builders::AutoScalingUpdateBuilder::default()
    }
}

/// A builder for [`AutoScalingUpdate`](crate::types::AutoScalingUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoScalingUpdateBuilder {
    pub(crate) max_worker_count: ::std::option::Option<i32>,
    pub(crate) mcu_count: ::std::option::Option<i32>,
    pub(crate) min_worker_count: ::std::option::Option<i32>,
    pub(crate) scale_in_policy: ::std::option::Option<crate::types::ScaleInPolicyUpdate>,
    pub(crate) scale_out_policy: ::std::option::Option<crate::types::ScaleOutPolicyUpdate>,
}
impl AutoScalingUpdateBuilder {
    /// <p>The target maximum number of workers allocated to the connector.</p>
    /// This field is required.
    pub fn max_worker_count(mut self, input: i32) -> Self {
        self.max_worker_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target maximum number of workers allocated to the connector.</p>
    pub fn set_max_worker_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_worker_count = input;
        self
    }
    /// <p>The target maximum number of workers allocated to the connector.</p>
    pub fn get_max_worker_count(&self) -> &::std::option::Option<i32> {
        &self.max_worker_count
    }
    /// <p>The target number of microcontroller units (MCUs) allocated to each connector worker. The valid values are 1,2,4,8.</p>
    /// This field is required.
    pub fn mcu_count(mut self, input: i32) -> Self {
        self.mcu_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target number of microcontroller units (MCUs) allocated to each connector worker. The valid values are 1,2,4,8.</p>
    pub fn set_mcu_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.mcu_count = input;
        self
    }
    /// <p>The target number of microcontroller units (MCUs) allocated to each connector worker. The valid values are 1,2,4,8.</p>
    pub fn get_mcu_count(&self) -> &::std::option::Option<i32> {
        &self.mcu_count
    }
    /// <p>The target minimum number of workers allocated to the connector.</p>
    /// This field is required.
    pub fn min_worker_count(mut self, input: i32) -> Self {
        self.min_worker_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target minimum number of workers allocated to the connector.</p>
    pub fn set_min_worker_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_worker_count = input;
        self
    }
    /// <p>The target minimum number of workers allocated to the connector.</p>
    pub fn get_min_worker_count(&self) -> &::std::option::Option<i32> {
        &self.min_worker_count
    }
    /// <p>The target sacle-in policy for the connector.</p>
    /// This field is required.
    pub fn scale_in_policy(mut self, input: crate::types::ScaleInPolicyUpdate) -> Self {
        self.scale_in_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target sacle-in policy for the connector.</p>
    pub fn set_scale_in_policy(mut self, input: ::std::option::Option<crate::types::ScaleInPolicyUpdate>) -> Self {
        self.scale_in_policy = input;
        self
    }
    /// <p>The target sacle-in policy for the connector.</p>
    pub fn get_scale_in_policy(&self) -> &::std::option::Option<crate::types::ScaleInPolicyUpdate> {
        &self.scale_in_policy
    }
    /// <p>The target sacle-out policy for the connector.</p>
    /// This field is required.
    pub fn scale_out_policy(mut self, input: crate::types::ScaleOutPolicyUpdate) -> Self {
        self.scale_out_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target sacle-out policy for the connector.</p>
    pub fn set_scale_out_policy(mut self, input: ::std::option::Option<crate::types::ScaleOutPolicyUpdate>) -> Self {
        self.scale_out_policy = input;
        self
    }
    /// <p>The target sacle-out policy for the connector.</p>
    pub fn get_scale_out_policy(&self) -> &::std::option::Option<crate::types::ScaleOutPolicyUpdate> {
        &self.scale_out_policy
    }
    /// Consumes the builder and constructs a [`AutoScalingUpdate`](crate::types::AutoScalingUpdate).
    pub fn build(self) -> crate::types::AutoScalingUpdate {
        crate::types::AutoScalingUpdate {
            max_worker_count: self.max_worker_count.unwrap_or_default(),
            mcu_count: self.mcu_count.unwrap_or_default(),
            min_worker_count: self.min_worker_count.unwrap_or_default(),
            scale_in_policy: self.scale_in_policy,
            scale_out_policy: self.scale_out_policy,
        }
    }
}
