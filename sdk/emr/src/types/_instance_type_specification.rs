// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration specification for each instance type in an instance fleet.</p><note>
/// <p>The instance fleet configuration is available only in Amazon EMR releases 4.8.0 and later, excluding 5.0.x versions.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstanceTypeSpecification {
    /// <p>The Amazon EC2 instance type, for example <code>m3.xlarge</code>.</p>
    pub instance_type: ::std::option::Option<::std::string::String>,
    /// <p>The number of units that a provisioned instance of this type provides toward fulfilling the target capacities defined in <code>InstanceFleetConfig</code>. Capacity values represent performance characteristics such as vCPUs, memory, or I/O. If not specified, the default value is 1.</p>
    pub weighted_capacity: ::std::option::Option<i32>,
    /// <p>The bid price for each Amazon EC2 Spot Instance type as defined by <code>InstanceType</code>. Expressed in USD.</p>
    pub bid_price: ::std::option::Option<::std::string::String>,
    /// <p>The bid price, as a percentage of On-Demand price, for each Amazon EC2 Spot Instance as defined by <code>InstanceType</code>. Expressed as a number (for example, 20 specifies 20%).</p>
    pub bid_price_as_percentage_of_on_demand_price: ::std::option::Option<f64>,
    /// <p>A configuration classification that applies when provisioning cluster instances, which can include configurations for applications and software bundled with Amazon EMR.</p>
    pub configurations: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>,
    /// <p>The configuration of Amazon Elastic Block Store (Amazon EBS) attached to each instance as defined by <code>InstanceType</code>.</p>
    pub ebs_block_devices: ::std::option::Option<::std::vec::Vec<crate::types::EbsBlockDevice>>,
    /// <p>Evaluates to <code>TRUE</code> when the specified <code>InstanceType</code> is EBS-optimized.</p>
    pub ebs_optimized: ::std::option::Option<bool>,
    /// <p>The custom AMI ID to use for the instance type.</p>
    pub custom_ami_id: ::std::option::Option<::std::string::String>,
    /// <p>The priority at which Amazon EMR launches the Amazon EC2 instances with this instance type. Priority starts at 0, which is the highest priority. Amazon EMR considers the highest priority first.</p>
    pub priority: ::std::option::Option<f64>,
}
impl InstanceTypeSpecification {
    /// <p>The Amazon EC2 instance type, for example <code>m3.xlarge</code>.</p>
    pub fn instance_type(&self) -> ::std::option::Option<&str> {
        self.instance_type.as_deref()
    }
    /// <p>The number of units that a provisioned instance of this type provides toward fulfilling the target capacities defined in <code>InstanceFleetConfig</code>. Capacity values represent performance characteristics such as vCPUs, memory, or I/O. If not specified, the default value is 1.</p>
    pub fn weighted_capacity(&self) -> ::std::option::Option<i32> {
        self.weighted_capacity
    }
    /// <p>The bid price for each Amazon EC2 Spot Instance type as defined by <code>InstanceType</code>. Expressed in USD.</p>
    pub fn bid_price(&self) -> ::std::option::Option<&str> {
        self.bid_price.as_deref()
    }
    /// <p>The bid price, as a percentage of On-Demand price, for each Amazon EC2 Spot Instance as defined by <code>InstanceType</code>. Expressed as a number (for example, 20 specifies 20%).</p>
    pub fn bid_price_as_percentage_of_on_demand_price(&self) -> ::std::option::Option<f64> {
        self.bid_price_as_percentage_of_on_demand_price
    }
    /// <p>A configuration classification that applies when provisioning cluster instances, which can include configurations for applications and software bundled with Amazon EMR.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.configurations.is_none()`.
    pub fn configurations(&self) -> &[crate::types::Configuration] {
        self.configurations.as_deref().unwrap_or_default()
    }
    /// <p>The configuration of Amazon Elastic Block Store (Amazon EBS) attached to each instance as defined by <code>InstanceType</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ebs_block_devices.is_none()`.
    pub fn ebs_block_devices(&self) -> &[crate::types::EbsBlockDevice] {
        self.ebs_block_devices.as_deref().unwrap_or_default()
    }
    /// <p>Evaluates to <code>TRUE</code> when the specified <code>InstanceType</code> is EBS-optimized.</p>
    pub fn ebs_optimized(&self) -> ::std::option::Option<bool> {
        self.ebs_optimized
    }
    /// <p>The custom AMI ID to use for the instance type.</p>
    pub fn custom_ami_id(&self) -> ::std::option::Option<&str> {
        self.custom_ami_id.as_deref()
    }
    /// <p>The priority at which Amazon EMR launches the Amazon EC2 instances with this instance type. Priority starts at 0, which is the highest priority. Amazon EMR considers the highest priority first.</p>
    pub fn priority(&self) -> ::std::option::Option<f64> {
        self.priority
    }
}
impl InstanceTypeSpecification {
    /// Creates a new builder-style object to manufacture [`InstanceTypeSpecification`](crate::types::InstanceTypeSpecification).
    pub fn builder() -> crate::types::builders::InstanceTypeSpecificationBuilder {
        crate::types::builders::InstanceTypeSpecificationBuilder::default()
    }
}

/// A builder for [`InstanceTypeSpecification`](crate::types::InstanceTypeSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstanceTypeSpecificationBuilder {
    pub(crate) instance_type: ::std::option::Option<::std::string::String>,
    pub(crate) weighted_capacity: ::std::option::Option<i32>,
    pub(crate) bid_price: ::std::option::Option<::std::string::String>,
    pub(crate) bid_price_as_percentage_of_on_demand_price: ::std::option::Option<f64>,
    pub(crate) configurations: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>,
    pub(crate) ebs_block_devices: ::std::option::Option<::std::vec::Vec<crate::types::EbsBlockDevice>>,
    pub(crate) ebs_optimized: ::std::option::Option<bool>,
    pub(crate) custom_ami_id: ::std::option::Option<::std::string::String>,
    pub(crate) priority: ::std::option::Option<f64>,
}
impl InstanceTypeSpecificationBuilder {
    /// <p>The Amazon EC2 instance type, for example <code>m3.xlarge</code>.</p>
    pub fn instance_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon EC2 instance type, for example <code>m3.xlarge</code>.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The Amazon EC2 instance type, for example <code>m3.xlarge</code>.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_type
    }
    /// <p>The number of units that a provisioned instance of this type provides toward fulfilling the target capacities defined in <code>InstanceFleetConfig</code>. Capacity values represent performance characteristics such as vCPUs, memory, or I/O. If not specified, the default value is 1.</p>
    pub fn weighted_capacity(mut self, input: i32) -> Self {
        self.weighted_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of units that a provisioned instance of this type provides toward fulfilling the target capacities defined in <code>InstanceFleetConfig</code>. Capacity values represent performance characteristics such as vCPUs, memory, or I/O. If not specified, the default value is 1.</p>
    pub fn set_weighted_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.weighted_capacity = input;
        self
    }
    /// <p>The number of units that a provisioned instance of this type provides toward fulfilling the target capacities defined in <code>InstanceFleetConfig</code>. Capacity values represent performance characteristics such as vCPUs, memory, or I/O. If not specified, the default value is 1.</p>
    pub fn get_weighted_capacity(&self) -> &::std::option::Option<i32> {
        &self.weighted_capacity
    }
    /// <p>The bid price for each Amazon EC2 Spot Instance type as defined by <code>InstanceType</code>. Expressed in USD.</p>
    pub fn bid_price(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bid_price = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The bid price for each Amazon EC2 Spot Instance type as defined by <code>InstanceType</code>. Expressed in USD.</p>
    pub fn set_bid_price(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bid_price = input;
        self
    }
    /// <p>The bid price for each Amazon EC2 Spot Instance type as defined by <code>InstanceType</code>. Expressed in USD.</p>
    pub fn get_bid_price(&self) -> &::std::option::Option<::std::string::String> {
        &self.bid_price
    }
    /// <p>The bid price, as a percentage of On-Demand price, for each Amazon EC2 Spot Instance as defined by <code>InstanceType</code>. Expressed as a number (for example, 20 specifies 20%).</p>
    pub fn bid_price_as_percentage_of_on_demand_price(mut self, input: f64) -> Self {
        self.bid_price_as_percentage_of_on_demand_price = ::std::option::Option::Some(input);
        self
    }
    /// <p>The bid price, as a percentage of On-Demand price, for each Amazon EC2 Spot Instance as defined by <code>InstanceType</code>. Expressed as a number (for example, 20 specifies 20%).</p>
    pub fn set_bid_price_as_percentage_of_on_demand_price(mut self, input: ::std::option::Option<f64>) -> Self {
        self.bid_price_as_percentage_of_on_demand_price = input;
        self
    }
    /// <p>The bid price, as a percentage of On-Demand price, for each Amazon EC2 Spot Instance as defined by <code>InstanceType</code>. Expressed as a number (for example, 20 specifies 20%).</p>
    pub fn get_bid_price_as_percentage_of_on_demand_price(&self) -> &::std::option::Option<f64> {
        &self.bid_price_as_percentage_of_on_demand_price
    }
    /// Appends an item to `configurations`.
    ///
    /// To override the contents of this collection use [`set_configurations`](Self::set_configurations).
    ///
    /// <p>A configuration classification that applies when provisioning cluster instances, which can include configurations for applications and software bundled with Amazon EMR.</p>
    pub fn configurations(mut self, input: crate::types::Configuration) -> Self {
        let mut v = self.configurations.unwrap_or_default();
        v.push(input);
        self.configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A configuration classification that applies when provisioning cluster instances, which can include configurations for applications and software bundled with Amazon EMR.</p>
    pub fn set_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>) -> Self {
        self.configurations = input;
        self
    }
    /// <p>A configuration classification that applies when provisioning cluster instances, which can include configurations for applications and software bundled with Amazon EMR.</p>
    pub fn get_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Configuration>> {
        &self.configurations
    }
    /// Appends an item to `ebs_block_devices`.
    ///
    /// To override the contents of this collection use [`set_ebs_block_devices`](Self::set_ebs_block_devices).
    ///
    /// <p>The configuration of Amazon Elastic Block Store (Amazon EBS) attached to each instance as defined by <code>InstanceType</code>.</p>
    pub fn ebs_block_devices(mut self, input: crate::types::EbsBlockDevice) -> Self {
        let mut v = self.ebs_block_devices.unwrap_or_default();
        v.push(input);
        self.ebs_block_devices = ::std::option::Option::Some(v);
        self
    }
    /// <p>The configuration of Amazon Elastic Block Store (Amazon EBS) attached to each instance as defined by <code>InstanceType</code>.</p>
    pub fn set_ebs_block_devices(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EbsBlockDevice>>) -> Self {
        self.ebs_block_devices = input;
        self
    }
    /// <p>The configuration of Amazon Elastic Block Store (Amazon EBS) attached to each instance as defined by <code>InstanceType</code>.</p>
    pub fn get_ebs_block_devices(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EbsBlockDevice>> {
        &self.ebs_block_devices
    }
    /// <p>Evaluates to <code>TRUE</code> when the specified <code>InstanceType</code> is EBS-optimized.</p>
    pub fn ebs_optimized(mut self, input: bool) -> Self {
        self.ebs_optimized = ::std::option::Option::Some(input);
        self
    }
    /// <p>Evaluates to <code>TRUE</code> when the specified <code>InstanceType</code> is EBS-optimized.</p>
    pub fn set_ebs_optimized(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ebs_optimized = input;
        self
    }
    /// <p>Evaluates to <code>TRUE</code> when the specified <code>InstanceType</code> is EBS-optimized.</p>
    pub fn get_ebs_optimized(&self) -> &::std::option::Option<bool> {
        &self.ebs_optimized
    }
    /// <p>The custom AMI ID to use for the instance type.</p>
    pub fn custom_ami_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_ami_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom AMI ID to use for the instance type.</p>
    pub fn set_custom_ami_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_ami_id = input;
        self
    }
    /// <p>The custom AMI ID to use for the instance type.</p>
    pub fn get_custom_ami_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_ami_id
    }
    /// <p>The priority at which Amazon EMR launches the Amazon EC2 instances with this instance type. Priority starts at 0, which is the highest priority. Amazon EMR considers the highest priority first.</p>
    pub fn priority(mut self, input: f64) -> Self {
        self.priority = ::std::option::Option::Some(input);
        self
    }
    /// <p>The priority at which Amazon EMR launches the Amazon EC2 instances with this instance type. Priority starts at 0, which is the highest priority. Amazon EMR considers the highest priority first.</p>
    pub fn set_priority(mut self, input: ::std::option::Option<f64>) -> Self {
        self.priority = input;
        self
    }
    /// <p>The priority at which Amazon EMR launches the Amazon EC2 instances with this instance type. Priority starts at 0, which is the highest priority. Amazon EMR considers the highest priority first.</p>
    pub fn get_priority(&self) -> &::std::option::Option<f64> {
        &self.priority
    }
    /// Consumes the builder and constructs a [`InstanceTypeSpecification`](crate::types::InstanceTypeSpecification).
    pub fn build(self) -> crate::types::InstanceTypeSpecification {
        crate::types::InstanceTypeSpecification {
            instance_type: self.instance_type,
            weighted_capacity: self.weighted_capacity,
            bid_price: self.bid_price,
            bid_price_as_percentage_of_on_demand_price: self.bid_price_as_percentage_of_on_demand_price,
            configurations: self.configurations,
            ebs_block_devices: self.ebs_block_devices,
            ebs_optimized: self.ebs_optimized,
            custom_ami_id: self.custom_ami_id,
            priority: self.priority,
        }
    }
}
