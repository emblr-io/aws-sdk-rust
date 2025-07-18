// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Utilization metrics for the instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Ec2ResourceUtilization {
    /// <p>The maximum observed or expected CPU utilization of the instance.</p>
    pub max_cpu_utilization_percentage: ::std::option::Option<::std::string::String>,
    /// <p>The maximum observed or expected memory utilization of the instance.</p>
    pub max_memory_utilization_percentage: ::std::option::Option<::std::string::String>,
    /// <p>The maximum observed or expected storage utilization of the instance. This doesn't include EBS storage.</p>
    pub max_storage_utilization_percentage: ::std::option::Option<::std::string::String>,
    /// <p>The EBS field that contains a list of EBS metrics that are associated with the current instance.</p>
    pub ebs_resource_utilization: ::std::option::Option<crate::types::EbsResourceUtilization>,
    /// <p>The field that contains a list of disk (local storage) metrics that are associated with the current instance.</p>
    pub disk_resource_utilization: ::std::option::Option<crate::types::DiskResourceUtilization>,
    /// <p>The network field that contains a list of network metrics that are associated with the current instance.</p>
    pub network_resource_utilization: ::std::option::Option<crate::types::NetworkResourceUtilization>,
}
impl Ec2ResourceUtilization {
    /// <p>The maximum observed or expected CPU utilization of the instance.</p>
    pub fn max_cpu_utilization_percentage(&self) -> ::std::option::Option<&str> {
        self.max_cpu_utilization_percentage.as_deref()
    }
    /// <p>The maximum observed or expected memory utilization of the instance.</p>
    pub fn max_memory_utilization_percentage(&self) -> ::std::option::Option<&str> {
        self.max_memory_utilization_percentage.as_deref()
    }
    /// <p>The maximum observed or expected storage utilization of the instance. This doesn't include EBS storage.</p>
    pub fn max_storage_utilization_percentage(&self) -> ::std::option::Option<&str> {
        self.max_storage_utilization_percentage.as_deref()
    }
    /// <p>The EBS field that contains a list of EBS metrics that are associated with the current instance.</p>
    pub fn ebs_resource_utilization(&self) -> ::std::option::Option<&crate::types::EbsResourceUtilization> {
        self.ebs_resource_utilization.as_ref()
    }
    /// <p>The field that contains a list of disk (local storage) metrics that are associated with the current instance.</p>
    pub fn disk_resource_utilization(&self) -> ::std::option::Option<&crate::types::DiskResourceUtilization> {
        self.disk_resource_utilization.as_ref()
    }
    /// <p>The network field that contains a list of network metrics that are associated with the current instance.</p>
    pub fn network_resource_utilization(&self) -> ::std::option::Option<&crate::types::NetworkResourceUtilization> {
        self.network_resource_utilization.as_ref()
    }
}
impl Ec2ResourceUtilization {
    /// Creates a new builder-style object to manufacture [`Ec2ResourceUtilization`](crate::types::Ec2ResourceUtilization).
    pub fn builder() -> crate::types::builders::Ec2ResourceUtilizationBuilder {
        crate::types::builders::Ec2ResourceUtilizationBuilder::default()
    }
}

/// A builder for [`Ec2ResourceUtilization`](crate::types::Ec2ResourceUtilization).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Ec2ResourceUtilizationBuilder {
    pub(crate) max_cpu_utilization_percentage: ::std::option::Option<::std::string::String>,
    pub(crate) max_memory_utilization_percentage: ::std::option::Option<::std::string::String>,
    pub(crate) max_storage_utilization_percentage: ::std::option::Option<::std::string::String>,
    pub(crate) ebs_resource_utilization: ::std::option::Option<crate::types::EbsResourceUtilization>,
    pub(crate) disk_resource_utilization: ::std::option::Option<crate::types::DiskResourceUtilization>,
    pub(crate) network_resource_utilization: ::std::option::Option<crate::types::NetworkResourceUtilization>,
}
impl Ec2ResourceUtilizationBuilder {
    /// <p>The maximum observed or expected CPU utilization of the instance.</p>
    pub fn max_cpu_utilization_percentage(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.max_cpu_utilization_percentage = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum observed or expected CPU utilization of the instance.</p>
    pub fn set_max_cpu_utilization_percentage(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.max_cpu_utilization_percentage = input;
        self
    }
    /// <p>The maximum observed or expected CPU utilization of the instance.</p>
    pub fn get_max_cpu_utilization_percentage(&self) -> &::std::option::Option<::std::string::String> {
        &self.max_cpu_utilization_percentage
    }
    /// <p>The maximum observed or expected memory utilization of the instance.</p>
    pub fn max_memory_utilization_percentage(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.max_memory_utilization_percentage = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum observed or expected memory utilization of the instance.</p>
    pub fn set_max_memory_utilization_percentage(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.max_memory_utilization_percentage = input;
        self
    }
    /// <p>The maximum observed or expected memory utilization of the instance.</p>
    pub fn get_max_memory_utilization_percentage(&self) -> &::std::option::Option<::std::string::String> {
        &self.max_memory_utilization_percentage
    }
    /// <p>The maximum observed or expected storage utilization of the instance. This doesn't include EBS storage.</p>
    pub fn max_storage_utilization_percentage(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.max_storage_utilization_percentage = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum observed or expected storage utilization of the instance. This doesn't include EBS storage.</p>
    pub fn set_max_storage_utilization_percentage(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.max_storage_utilization_percentage = input;
        self
    }
    /// <p>The maximum observed or expected storage utilization of the instance. This doesn't include EBS storage.</p>
    pub fn get_max_storage_utilization_percentage(&self) -> &::std::option::Option<::std::string::String> {
        &self.max_storage_utilization_percentage
    }
    /// <p>The EBS field that contains a list of EBS metrics that are associated with the current instance.</p>
    pub fn ebs_resource_utilization(mut self, input: crate::types::EbsResourceUtilization) -> Self {
        self.ebs_resource_utilization = ::std::option::Option::Some(input);
        self
    }
    /// <p>The EBS field that contains a list of EBS metrics that are associated with the current instance.</p>
    pub fn set_ebs_resource_utilization(mut self, input: ::std::option::Option<crate::types::EbsResourceUtilization>) -> Self {
        self.ebs_resource_utilization = input;
        self
    }
    /// <p>The EBS field that contains a list of EBS metrics that are associated with the current instance.</p>
    pub fn get_ebs_resource_utilization(&self) -> &::std::option::Option<crate::types::EbsResourceUtilization> {
        &self.ebs_resource_utilization
    }
    /// <p>The field that contains a list of disk (local storage) metrics that are associated with the current instance.</p>
    pub fn disk_resource_utilization(mut self, input: crate::types::DiskResourceUtilization) -> Self {
        self.disk_resource_utilization = ::std::option::Option::Some(input);
        self
    }
    /// <p>The field that contains a list of disk (local storage) metrics that are associated with the current instance.</p>
    pub fn set_disk_resource_utilization(mut self, input: ::std::option::Option<crate::types::DiskResourceUtilization>) -> Self {
        self.disk_resource_utilization = input;
        self
    }
    /// <p>The field that contains a list of disk (local storage) metrics that are associated with the current instance.</p>
    pub fn get_disk_resource_utilization(&self) -> &::std::option::Option<crate::types::DiskResourceUtilization> {
        &self.disk_resource_utilization
    }
    /// <p>The network field that contains a list of network metrics that are associated with the current instance.</p>
    pub fn network_resource_utilization(mut self, input: crate::types::NetworkResourceUtilization) -> Self {
        self.network_resource_utilization = ::std::option::Option::Some(input);
        self
    }
    /// <p>The network field that contains a list of network metrics that are associated with the current instance.</p>
    pub fn set_network_resource_utilization(mut self, input: ::std::option::Option<crate::types::NetworkResourceUtilization>) -> Self {
        self.network_resource_utilization = input;
        self
    }
    /// <p>The network field that contains a list of network metrics that are associated with the current instance.</p>
    pub fn get_network_resource_utilization(&self) -> &::std::option::Option<crate::types::NetworkResourceUtilization> {
        &self.network_resource_utilization
    }
    /// Consumes the builder and constructs a [`Ec2ResourceUtilization`](crate::types::Ec2ResourceUtilization).
    pub fn build(self) -> crate::types::Ec2ResourceUtilization {
        crate::types::Ec2ResourceUtilization {
            max_cpu_utilization_percentage: self.max_cpu_utilization_percentage,
            max_memory_utilization_percentage: self.max_memory_utilization_percentage,
            max_storage_utilization_percentage: self.max_storage_utilization_percentage,
            ebs_resource_utilization: self.ebs_resource_utilization,
            disk_resource_utilization: self.disk_resource_utilization,
            network_resource_utilization: self.network_resource_utilization,
        }
    }
}
