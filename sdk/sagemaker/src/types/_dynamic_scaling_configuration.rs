// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object with the recommended values for you to specify when creating an autoscaling policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DynamicScalingConfiguration {
    /// <p>The recommended minimum capacity to specify for your autoscaling policy.</p>
    pub min_capacity: ::std::option::Option<i32>,
    /// <p>The recommended maximum capacity to specify for your autoscaling policy.</p>
    pub max_capacity: ::std::option::Option<i32>,
    /// <p>The recommended scale in cooldown time for your autoscaling policy.</p>
    pub scale_in_cooldown: ::std::option::Option<i32>,
    /// <p>The recommended scale out cooldown time for your autoscaling policy.</p>
    pub scale_out_cooldown: ::std::option::Option<i32>,
    /// <p>An object of the scaling policies for each metric.</p>
    pub scaling_policies: ::std::option::Option<::std::vec::Vec<crate::types::ScalingPolicy>>,
}
impl DynamicScalingConfiguration {
    /// <p>The recommended minimum capacity to specify for your autoscaling policy.</p>
    pub fn min_capacity(&self) -> ::std::option::Option<i32> {
        self.min_capacity
    }
    /// <p>The recommended maximum capacity to specify for your autoscaling policy.</p>
    pub fn max_capacity(&self) -> ::std::option::Option<i32> {
        self.max_capacity
    }
    /// <p>The recommended scale in cooldown time for your autoscaling policy.</p>
    pub fn scale_in_cooldown(&self) -> ::std::option::Option<i32> {
        self.scale_in_cooldown
    }
    /// <p>The recommended scale out cooldown time for your autoscaling policy.</p>
    pub fn scale_out_cooldown(&self) -> ::std::option::Option<i32> {
        self.scale_out_cooldown
    }
    /// <p>An object of the scaling policies for each metric.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.scaling_policies.is_none()`.
    pub fn scaling_policies(&self) -> &[crate::types::ScalingPolicy] {
        self.scaling_policies.as_deref().unwrap_or_default()
    }
}
impl DynamicScalingConfiguration {
    /// Creates a new builder-style object to manufacture [`DynamicScalingConfiguration`](crate::types::DynamicScalingConfiguration).
    pub fn builder() -> crate::types::builders::DynamicScalingConfigurationBuilder {
        crate::types::builders::DynamicScalingConfigurationBuilder::default()
    }
}

/// A builder for [`DynamicScalingConfiguration`](crate::types::DynamicScalingConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DynamicScalingConfigurationBuilder {
    pub(crate) min_capacity: ::std::option::Option<i32>,
    pub(crate) max_capacity: ::std::option::Option<i32>,
    pub(crate) scale_in_cooldown: ::std::option::Option<i32>,
    pub(crate) scale_out_cooldown: ::std::option::Option<i32>,
    pub(crate) scaling_policies: ::std::option::Option<::std::vec::Vec<crate::types::ScalingPolicy>>,
}
impl DynamicScalingConfigurationBuilder {
    /// <p>The recommended minimum capacity to specify for your autoscaling policy.</p>
    pub fn min_capacity(mut self, input: i32) -> Self {
        self.min_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The recommended minimum capacity to specify for your autoscaling policy.</p>
    pub fn set_min_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_capacity = input;
        self
    }
    /// <p>The recommended minimum capacity to specify for your autoscaling policy.</p>
    pub fn get_min_capacity(&self) -> &::std::option::Option<i32> {
        &self.min_capacity
    }
    /// <p>The recommended maximum capacity to specify for your autoscaling policy.</p>
    pub fn max_capacity(mut self, input: i32) -> Self {
        self.max_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The recommended maximum capacity to specify for your autoscaling policy.</p>
    pub fn set_max_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_capacity = input;
        self
    }
    /// <p>The recommended maximum capacity to specify for your autoscaling policy.</p>
    pub fn get_max_capacity(&self) -> &::std::option::Option<i32> {
        &self.max_capacity
    }
    /// <p>The recommended scale in cooldown time for your autoscaling policy.</p>
    pub fn scale_in_cooldown(mut self, input: i32) -> Self {
        self.scale_in_cooldown = ::std::option::Option::Some(input);
        self
    }
    /// <p>The recommended scale in cooldown time for your autoscaling policy.</p>
    pub fn set_scale_in_cooldown(mut self, input: ::std::option::Option<i32>) -> Self {
        self.scale_in_cooldown = input;
        self
    }
    /// <p>The recommended scale in cooldown time for your autoscaling policy.</p>
    pub fn get_scale_in_cooldown(&self) -> &::std::option::Option<i32> {
        &self.scale_in_cooldown
    }
    /// <p>The recommended scale out cooldown time for your autoscaling policy.</p>
    pub fn scale_out_cooldown(mut self, input: i32) -> Self {
        self.scale_out_cooldown = ::std::option::Option::Some(input);
        self
    }
    /// <p>The recommended scale out cooldown time for your autoscaling policy.</p>
    pub fn set_scale_out_cooldown(mut self, input: ::std::option::Option<i32>) -> Self {
        self.scale_out_cooldown = input;
        self
    }
    /// <p>The recommended scale out cooldown time for your autoscaling policy.</p>
    pub fn get_scale_out_cooldown(&self) -> &::std::option::Option<i32> {
        &self.scale_out_cooldown
    }
    /// Appends an item to `scaling_policies`.
    ///
    /// To override the contents of this collection use [`set_scaling_policies`](Self::set_scaling_policies).
    ///
    /// <p>An object of the scaling policies for each metric.</p>
    pub fn scaling_policies(mut self, input: crate::types::ScalingPolicy) -> Self {
        let mut v = self.scaling_policies.unwrap_or_default();
        v.push(input);
        self.scaling_policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>An object of the scaling policies for each metric.</p>
    pub fn set_scaling_policies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ScalingPolicy>>) -> Self {
        self.scaling_policies = input;
        self
    }
    /// <p>An object of the scaling policies for each metric.</p>
    pub fn get_scaling_policies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ScalingPolicy>> {
        &self.scaling_policies
    }
    /// Consumes the builder and constructs a [`DynamicScalingConfiguration`](crate::types::DynamicScalingConfiguration).
    pub fn build(self) -> crate::types::DynamicScalingConfiguration {
        crate::types::DynamicScalingConfiguration {
            min_capacity: self.min_capacity,
            max_capacity: self.max_capacity,
            scale_in_cooldown: self.scale_in_cooldown,
            scale_out_cooldown: self.scale_out_cooldown,
            scaling_policies: self.scaling_policies,
        }
    }
}
