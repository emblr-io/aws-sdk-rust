// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the instances distribution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails {
    /// <p>How to allocate instance types to fulfill On-Demand capacity. The valid value is <code>prioritized</code>.</p>
    pub on_demand_allocation_strategy: ::std::option::Option<::std::string::String>,
    /// <p>The minimum amount of the Auto Scaling group's capacity that must be fulfilled by On-Demand Instances.</p>
    pub on_demand_base_capacity: ::std::option::Option<i32>,
    /// <p>The percentage of On-Demand Instances and Spot Instances for additional capacity beyond <code>OnDemandBaseCapacity</code>.</p>
    pub on_demand_percentage_above_base_capacity: ::std::option::Option<i32>,
    /// <p>How to allocate instances across Spot Instance pools. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>lowest-price</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized-prioritized</code></p></li>
    /// </ul>
    pub spot_allocation_strategy: ::std::option::Option<::std::string::String>,
    /// <p>The number of Spot Instance pools across which to allocate your Spot Instances.</p>
    pub spot_instance_pools: ::std::option::Option<i32>,
    /// <p>The maximum price per unit hour that you are willing to pay for a Spot Instance.</p>
    pub spot_max_price: ::std::option::Option<::std::string::String>,
}
impl AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails {
    /// <p>How to allocate instance types to fulfill On-Demand capacity. The valid value is <code>prioritized</code>.</p>
    pub fn on_demand_allocation_strategy(&self) -> ::std::option::Option<&str> {
        self.on_demand_allocation_strategy.as_deref()
    }
    /// <p>The minimum amount of the Auto Scaling group's capacity that must be fulfilled by On-Demand Instances.</p>
    pub fn on_demand_base_capacity(&self) -> ::std::option::Option<i32> {
        self.on_demand_base_capacity
    }
    /// <p>The percentage of On-Demand Instances and Spot Instances for additional capacity beyond <code>OnDemandBaseCapacity</code>.</p>
    pub fn on_demand_percentage_above_base_capacity(&self) -> ::std::option::Option<i32> {
        self.on_demand_percentage_above_base_capacity
    }
    /// <p>How to allocate instances across Spot Instance pools. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>lowest-price</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized-prioritized</code></p></li>
    /// </ul>
    pub fn spot_allocation_strategy(&self) -> ::std::option::Option<&str> {
        self.spot_allocation_strategy.as_deref()
    }
    /// <p>The number of Spot Instance pools across which to allocate your Spot Instances.</p>
    pub fn spot_instance_pools(&self) -> ::std::option::Option<i32> {
        self.spot_instance_pools
    }
    /// <p>The maximum price per unit hour that you are willing to pay for a Spot Instance.</p>
    pub fn spot_max_price(&self) -> ::std::option::Option<&str> {
        self.spot_max_price.as_deref()
    }
}
impl AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails {
    /// Creates a new builder-style object to manufacture [`AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails`](crate::types::AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails).
    pub fn builder() -> crate::types::builders::AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetailsBuilder {
        crate::types::builders::AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetailsBuilder::default()
    }
}

/// A builder for [`AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails`](crate::types::AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetailsBuilder {
    pub(crate) on_demand_allocation_strategy: ::std::option::Option<::std::string::String>,
    pub(crate) on_demand_base_capacity: ::std::option::Option<i32>,
    pub(crate) on_demand_percentage_above_base_capacity: ::std::option::Option<i32>,
    pub(crate) spot_allocation_strategy: ::std::option::Option<::std::string::String>,
    pub(crate) spot_instance_pools: ::std::option::Option<i32>,
    pub(crate) spot_max_price: ::std::option::Option<::std::string::String>,
}
impl AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetailsBuilder {
    /// <p>How to allocate instance types to fulfill On-Demand capacity. The valid value is <code>prioritized</code>.</p>
    pub fn on_demand_allocation_strategy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.on_demand_allocation_strategy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>How to allocate instance types to fulfill On-Demand capacity. The valid value is <code>prioritized</code>.</p>
    pub fn set_on_demand_allocation_strategy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.on_demand_allocation_strategy = input;
        self
    }
    /// <p>How to allocate instance types to fulfill On-Demand capacity. The valid value is <code>prioritized</code>.</p>
    pub fn get_on_demand_allocation_strategy(&self) -> &::std::option::Option<::std::string::String> {
        &self.on_demand_allocation_strategy
    }
    /// <p>The minimum amount of the Auto Scaling group's capacity that must be fulfilled by On-Demand Instances.</p>
    pub fn on_demand_base_capacity(mut self, input: i32) -> Self {
        self.on_demand_base_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum amount of the Auto Scaling group's capacity that must be fulfilled by On-Demand Instances.</p>
    pub fn set_on_demand_base_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.on_demand_base_capacity = input;
        self
    }
    /// <p>The minimum amount of the Auto Scaling group's capacity that must be fulfilled by On-Demand Instances.</p>
    pub fn get_on_demand_base_capacity(&self) -> &::std::option::Option<i32> {
        &self.on_demand_base_capacity
    }
    /// <p>The percentage of On-Demand Instances and Spot Instances for additional capacity beyond <code>OnDemandBaseCapacity</code>.</p>
    pub fn on_demand_percentage_above_base_capacity(mut self, input: i32) -> Self {
        self.on_demand_percentage_above_base_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage of On-Demand Instances and Spot Instances for additional capacity beyond <code>OnDemandBaseCapacity</code>.</p>
    pub fn set_on_demand_percentage_above_base_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.on_demand_percentage_above_base_capacity = input;
        self
    }
    /// <p>The percentage of On-Demand Instances and Spot Instances for additional capacity beyond <code>OnDemandBaseCapacity</code>.</p>
    pub fn get_on_demand_percentage_above_base_capacity(&self) -> &::std::option::Option<i32> {
        &self.on_demand_percentage_above_base_capacity
    }
    /// <p>How to allocate instances across Spot Instance pools. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>lowest-price</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized-prioritized</code></p></li>
    /// </ul>
    pub fn spot_allocation_strategy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.spot_allocation_strategy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>How to allocate instances across Spot Instance pools. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>lowest-price</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized-prioritized</code></p></li>
    /// </ul>
    pub fn set_spot_allocation_strategy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.spot_allocation_strategy = input;
        self
    }
    /// <p>How to allocate instances across Spot Instance pools. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>lowest-price</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized</code></p></li>
    /// <li>
    /// <p><code>capacity-optimized-prioritized</code></p></li>
    /// </ul>
    pub fn get_spot_allocation_strategy(&self) -> &::std::option::Option<::std::string::String> {
        &self.spot_allocation_strategy
    }
    /// <p>The number of Spot Instance pools across which to allocate your Spot Instances.</p>
    pub fn spot_instance_pools(mut self, input: i32) -> Self {
        self.spot_instance_pools = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of Spot Instance pools across which to allocate your Spot Instances.</p>
    pub fn set_spot_instance_pools(mut self, input: ::std::option::Option<i32>) -> Self {
        self.spot_instance_pools = input;
        self
    }
    /// <p>The number of Spot Instance pools across which to allocate your Spot Instances.</p>
    pub fn get_spot_instance_pools(&self) -> &::std::option::Option<i32> {
        &self.spot_instance_pools
    }
    /// <p>The maximum price per unit hour that you are willing to pay for a Spot Instance.</p>
    pub fn spot_max_price(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.spot_max_price = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum price per unit hour that you are willing to pay for a Spot Instance.</p>
    pub fn set_spot_max_price(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.spot_max_price = input;
        self
    }
    /// <p>The maximum price per unit hour that you are willing to pay for a Spot Instance.</p>
    pub fn get_spot_max_price(&self) -> &::std::option::Option<::std::string::String> {
        &self.spot_max_price
    }
    /// Consumes the builder and constructs a [`AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails`](crate::types::AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails).
    pub fn build(self) -> crate::types::AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails {
        crate::types::AwsAutoScalingAutoScalingGroupMixedInstancesPolicyInstancesDistributionDetails {
            on_demand_allocation_strategy: self.on_demand_allocation_strategy,
            on_demand_base_capacity: self.on_demand_base_capacity,
            on_demand_percentage_above_base_capacity: self.on_demand_percentage_above_base_capacity,
            spot_allocation_strategy: self.spot_allocation_strategy,
            spot_instance_pools: self.spot_instance_pools,
            spot_max_price: self.spot_max_price,
        }
    }
}
