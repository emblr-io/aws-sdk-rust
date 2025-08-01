// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about provisioned throughput for EBS storage volumes attached to kafka broker nodes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProvisionedThroughput {
    /// <p>Provisioned throughput is enabled or not.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>Throughput value of the EBS volumes for the data drive on each kafka broker node in MiB per second.</p>
    pub volume_throughput: ::std::option::Option<i32>,
}
impl ProvisionedThroughput {
    /// <p>Provisioned throughput is enabled or not.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>Throughput value of the EBS volumes for the data drive on each kafka broker node in MiB per second.</p>
    pub fn volume_throughput(&self) -> ::std::option::Option<i32> {
        self.volume_throughput
    }
}
impl ProvisionedThroughput {
    /// Creates a new builder-style object to manufacture [`ProvisionedThroughput`](crate::types::ProvisionedThroughput).
    pub fn builder() -> crate::types::builders::ProvisionedThroughputBuilder {
        crate::types::builders::ProvisionedThroughputBuilder::default()
    }
}

/// A builder for [`ProvisionedThroughput`](crate::types::ProvisionedThroughput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProvisionedThroughputBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) volume_throughput: ::std::option::Option<i32>,
}
impl ProvisionedThroughputBuilder {
    /// <p>Provisioned throughput is enabled or not.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provisioned throughput is enabled or not.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Provisioned throughput is enabled or not.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>Throughput value of the EBS volumes for the data drive on each kafka broker node in MiB per second.</p>
    pub fn volume_throughput(mut self, input: i32) -> Self {
        self.volume_throughput = ::std::option::Option::Some(input);
        self
    }
    /// <p>Throughput value of the EBS volumes for the data drive on each kafka broker node in MiB per second.</p>
    pub fn set_volume_throughput(mut self, input: ::std::option::Option<i32>) -> Self {
        self.volume_throughput = input;
        self
    }
    /// <p>Throughput value of the EBS volumes for the data drive on each kafka broker node in MiB per second.</p>
    pub fn get_volume_throughput(&self) -> &::std::option::Option<i32> {
        &self.volume_throughput
    }
    /// Consumes the builder and constructs a [`ProvisionedThroughput`](crate::types::ProvisionedThroughput).
    pub fn build(self) -> crate::types::ProvisionedThroughput {
        crate::types::ProvisionedThroughput {
            enabled: self.enabled,
            volume_throughput: self.volume_throughput,
        }
    }
}
