// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon EBS configuration of a cluster instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EbsConfiguration {
    /// <p>An array of Amazon EBS volume specifications attached to a cluster instance.</p>
    pub ebs_block_device_configs: ::std::option::Option<::std::vec::Vec<crate::types::EbsBlockDeviceConfig>>,
    /// <p>Indicates whether an Amazon EBS volume is EBS-optimized. The default is false. You should explicitly set this value to true to enable the Amazon EBS-optimized setting for an EC2 instance.</p>
    pub ebs_optimized: ::std::option::Option<bool>,
}
impl EbsConfiguration {
    /// <p>An array of Amazon EBS volume specifications attached to a cluster instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ebs_block_device_configs.is_none()`.
    pub fn ebs_block_device_configs(&self) -> &[crate::types::EbsBlockDeviceConfig] {
        self.ebs_block_device_configs.as_deref().unwrap_or_default()
    }
    /// <p>Indicates whether an Amazon EBS volume is EBS-optimized. The default is false. You should explicitly set this value to true to enable the Amazon EBS-optimized setting for an EC2 instance.</p>
    pub fn ebs_optimized(&self) -> ::std::option::Option<bool> {
        self.ebs_optimized
    }
}
impl EbsConfiguration {
    /// Creates a new builder-style object to manufacture [`EbsConfiguration`](crate::types::EbsConfiguration).
    pub fn builder() -> crate::types::builders::EbsConfigurationBuilder {
        crate::types::builders::EbsConfigurationBuilder::default()
    }
}

/// A builder for [`EbsConfiguration`](crate::types::EbsConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EbsConfigurationBuilder {
    pub(crate) ebs_block_device_configs: ::std::option::Option<::std::vec::Vec<crate::types::EbsBlockDeviceConfig>>,
    pub(crate) ebs_optimized: ::std::option::Option<bool>,
}
impl EbsConfigurationBuilder {
    /// Appends an item to `ebs_block_device_configs`.
    ///
    /// To override the contents of this collection use [`set_ebs_block_device_configs`](Self::set_ebs_block_device_configs).
    ///
    /// <p>An array of Amazon EBS volume specifications attached to a cluster instance.</p>
    pub fn ebs_block_device_configs(mut self, input: crate::types::EbsBlockDeviceConfig) -> Self {
        let mut v = self.ebs_block_device_configs.unwrap_or_default();
        v.push(input);
        self.ebs_block_device_configs = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of Amazon EBS volume specifications attached to a cluster instance.</p>
    pub fn set_ebs_block_device_configs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EbsBlockDeviceConfig>>) -> Self {
        self.ebs_block_device_configs = input;
        self
    }
    /// <p>An array of Amazon EBS volume specifications attached to a cluster instance.</p>
    pub fn get_ebs_block_device_configs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EbsBlockDeviceConfig>> {
        &self.ebs_block_device_configs
    }
    /// <p>Indicates whether an Amazon EBS volume is EBS-optimized. The default is false. You should explicitly set this value to true to enable the Amazon EBS-optimized setting for an EC2 instance.</p>
    pub fn ebs_optimized(mut self, input: bool) -> Self {
        self.ebs_optimized = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether an Amazon EBS volume is EBS-optimized. The default is false. You should explicitly set this value to true to enable the Amazon EBS-optimized setting for an EC2 instance.</p>
    pub fn set_ebs_optimized(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ebs_optimized = input;
        self
    }
    /// <p>Indicates whether an Amazon EBS volume is EBS-optimized. The default is false. You should explicitly set this value to true to enable the Amazon EBS-optimized setting for an EC2 instance.</p>
    pub fn get_ebs_optimized(&self) -> &::std::option::Option<bool> {
        &self.ebs_optimized
    }
    /// Consumes the builder and constructs a [`EbsConfiguration`](crate::types::EbsConfiguration).
    pub fn build(self) -> crate::types::EbsConfiguration {
        crate::types::EbsConfiguration {
            ebs_block_device_configs: self.ebs_block_device_configs,
            ebs_optimized: self.ebs_optimized,
        }
    }
}
