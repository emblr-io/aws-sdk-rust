// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides options for how often Config delivers configuration snapshots to the Amazon S3 bucket in your delivery channel.</p>
/// <p>The frequency for a rule that triggers evaluations for your resources when Config delivers the configuration snapshot is set by one of two values, depending on which is less frequent:</p>
/// <ul>
/// <li>
/// <p>The value for the <code>deliveryFrequency</code> parameter within the delivery channel configuration, which sets how often Config delivers configuration snapshots. This value also sets how often Config invokes evaluations for Config rules.</p></li>
/// <li>
/// <p>The value for the <code>MaximumExecutionFrequency</code> parameter, which sets the maximum frequency with which Config invokes evaluations for the rule. For more information, see <code>ConfigRule</code>.</p></li>
/// </ul>
/// <p>If the <code>deliveryFrequency</code> value is less frequent than the <code>MaximumExecutionFrequency</code> value for a rule, Config invokes the rule only as often as the <code>deliveryFrequency</code> value.</p>
/// <ol>
/// <li>
/// <p>For example, you want your rule to run evaluations when Config delivers the configuration snapshot.</p></li>
/// <li>
/// <p>You specify the <code>MaximumExecutionFrequency</code> value for <code>Six_Hours</code>.</p></li>
/// <li>
/// <p>You then specify the delivery channel <code>deliveryFrequency</code> value for <code>TwentyFour_Hours</code>.</p></li>
/// <li>
/// <p>Because the value for <code>deliveryFrequency</code> is less frequent than <code>MaximumExecutionFrequency</code>, Config invokes evaluations for the rule every 24 hours.</p></li>
/// </ol>
/// <p>You should set the <code>MaximumExecutionFrequency</code> value to be at least as frequent as the <code>deliveryFrequency</code> value. You can view the <code>deliveryFrequency</code> value by using the <code>DescribeDeliveryChannnels</code> action.</p>
/// <p>To update the <code>deliveryFrequency</code> with which Config delivers your configuration snapshots, use the <code>PutDeliveryChannel</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConfigSnapshotDeliveryProperties {
    /// <p>The frequency with which Config delivers configuration snapshots.</p>
    pub delivery_frequency: ::std::option::Option<crate::types::MaximumExecutionFrequency>,
}
impl ConfigSnapshotDeliveryProperties {
    /// <p>The frequency with which Config delivers configuration snapshots.</p>
    pub fn delivery_frequency(&self) -> ::std::option::Option<&crate::types::MaximumExecutionFrequency> {
        self.delivery_frequency.as_ref()
    }
}
impl ConfigSnapshotDeliveryProperties {
    /// Creates a new builder-style object to manufacture [`ConfigSnapshotDeliveryProperties`](crate::types::ConfigSnapshotDeliveryProperties).
    pub fn builder() -> crate::types::builders::ConfigSnapshotDeliveryPropertiesBuilder {
        crate::types::builders::ConfigSnapshotDeliveryPropertiesBuilder::default()
    }
}

/// A builder for [`ConfigSnapshotDeliveryProperties`](crate::types::ConfigSnapshotDeliveryProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfigSnapshotDeliveryPropertiesBuilder {
    pub(crate) delivery_frequency: ::std::option::Option<crate::types::MaximumExecutionFrequency>,
}
impl ConfigSnapshotDeliveryPropertiesBuilder {
    /// <p>The frequency with which Config delivers configuration snapshots.</p>
    pub fn delivery_frequency(mut self, input: crate::types::MaximumExecutionFrequency) -> Self {
        self.delivery_frequency = ::std::option::Option::Some(input);
        self
    }
    /// <p>The frequency with which Config delivers configuration snapshots.</p>
    pub fn set_delivery_frequency(mut self, input: ::std::option::Option<crate::types::MaximumExecutionFrequency>) -> Self {
        self.delivery_frequency = input;
        self
    }
    /// <p>The frequency with which Config delivers configuration snapshots.</p>
    pub fn get_delivery_frequency(&self) -> &::std::option::Option<crate::types::MaximumExecutionFrequency> {
        &self.delivery_frequency
    }
    /// Consumes the builder and constructs a [`ConfigSnapshotDeliveryProperties`](crate::types::ConfigSnapshotDeliveryProperties).
    pub fn build(self) -> crate::types::ConfigSnapshotDeliveryProperties {
        crate::types::ConfigSnapshotDeliveryProperties {
            delivery_frequency: self.delivery_frequency,
        }
    }
}
