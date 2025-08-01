// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information on the status of data sources for the detector.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataSourceConfigurationsResult {
    /// <p>An object that contains information on the status of CloudTrail as a data source.</p>
    pub cloud_trail: ::std::option::Option<crate::types::CloudTrailConfigurationResult>,
    /// <p>An object that contains information on the status of DNS logs as a data source.</p>
    pub dns_logs: ::std::option::Option<crate::types::DnsLogsConfigurationResult>,
    /// <p>An object that contains information on the status of VPC flow logs as a data source.</p>
    pub flow_logs: ::std::option::Option<crate::types::FlowLogsConfigurationResult>,
    /// <p>An object that contains information on the status of S3 Data event logs as a data source.</p>
    pub s3_logs: ::std::option::Option<crate::types::S3LogsConfigurationResult>,
    /// <p>An object that contains information on the status of all Kubernetes data sources.</p>
    pub kubernetes: ::std::option::Option<crate::types::KubernetesConfigurationResult>,
    /// <p>Describes the configuration of Malware Protection data sources.</p>
    pub malware_protection: ::std::option::Option<crate::types::MalwareProtectionConfigurationResult>,
}
impl DataSourceConfigurationsResult {
    /// <p>An object that contains information on the status of CloudTrail as a data source.</p>
    pub fn cloud_trail(&self) -> ::std::option::Option<&crate::types::CloudTrailConfigurationResult> {
        self.cloud_trail.as_ref()
    }
    /// <p>An object that contains information on the status of DNS logs as a data source.</p>
    pub fn dns_logs(&self) -> ::std::option::Option<&crate::types::DnsLogsConfigurationResult> {
        self.dns_logs.as_ref()
    }
    /// <p>An object that contains information on the status of VPC flow logs as a data source.</p>
    pub fn flow_logs(&self) -> ::std::option::Option<&crate::types::FlowLogsConfigurationResult> {
        self.flow_logs.as_ref()
    }
    /// <p>An object that contains information on the status of S3 Data event logs as a data source.</p>
    pub fn s3_logs(&self) -> ::std::option::Option<&crate::types::S3LogsConfigurationResult> {
        self.s3_logs.as_ref()
    }
    /// <p>An object that contains information on the status of all Kubernetes data sources.</p>
    pub fn kubernetes(&self) -> ::std::option::Option<&crate::types::KubernetesConfigurationResult> {
        self.kubernetes.as_ref()
    }
    /// <p>Describes the configuration of Malware Protection data sources.</p>
    pub fn malware_protection(&self) -> ::std::option::Option<&crate::types::MalwareProtectionConfigurationResult> {
        self.malware_protection.as_ref()
    }
}
impl DataSourceConfigurationsResult {
    /// Creates a new builder-style object to manufacture [`DataSourceConfigurationsResult`](crate::types::DataSourceConfigurationsResult).
    pub fn builder() -> crate::types::builders::DataSourceConfigurationsResultBuilder {
        crate::types::builders::DataSourceConfigurationsResultBuilder::default()
    }
}

/// A builder for [`DataSourceConfigurationsResult`](crate::types::DataSourceConfigurationsResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataSourceConfigurationsResultBuilder {
    pub(crate) cloud_trail: ::std::option::Option<crate::types::CloudTrailConfigurationResult>,
    pub(crate) dns_logs: ::std::option::Option<crate::types::DnsLogsConfigurationResult>,
    pub(crate) flow_logs: ::std::option::Option<crate::types::FlowLogsConfigurationResult>,
    pub(crate) s3_logs: ::std::option::Option<crate::types::S3LogsConfigurationResult>,
    pub(crate) kubernetes: ::std::option::Option<crate::types::KubernetesConfigurationResult>,
    pub(crate) malware_protection: ::std::option::Option<crate::types::MalwareProtectionConfigurationResult>,
}
impl DataSourceConfigurationsResultBuilder {
    /// <p>An object that contains information on the status of CloudTrail as a data source.</p>
    /// This field is required.
    pub fn cloud_trail(mut self, input: crate::types::CloudTrailConfigurationResult) -> Self {
        self.cloud_trail = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information on the status of CloudTrail as a data source.</p>
    pub fn set_cloud_trail(mut self, input: ::std::option::Option<crate::types::CloudTrailConfigurationResult>) -> Self {
        self.cloud_trail = input;
        self
    }
    /// <p>An object that contains information on the status of CloudTrail as a data source.</p>
    pub fn get_cloud_trail(&self) -> &::std::option::Option<crate::types::CloudTrailConfigurationResult> {
        &self.cloud_trail
    }
    /// <p>An object that contains information on the status of DNS logs as a data source.</p>
    /// This field is required.
    pub fn dns_logs(mut self, input: crate::types::DnsLogsConfigurationResult) -> Self {
        self.dns_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information on the status of DNS logs as a data source.</p>
    pub fn set_dns_logs(mut self, input: ::std::option::Option<crate::types::DnsLogsConfigurationResult>) -> Self {
        self.dns_logs = input;
        self
    }
    /// <p>An object that contains information on the status of DNS logs as a data source.</p>
    pub fn get_dns_logs(&self) -> &::std::option::Option<crate::types::DnsLogsConfigurationResult> {
        &self.dns_logs
    }
    /// <p>An object that contains information on the status of VPC flow logs as a data source.</p>
    /// This field is required.
    pub fn flow_logs(mut self, input: crate::types::FlowLogsConfigurationResult) -> Self {
        self.flow_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information on the status of VPC flow logs as a data source.</p>
    pub fn set_flow_logs(mut self, input: ::std::option::Option<crate::types::FlowLogsConfigurationResult>) -> Self {
        self.flow_logs = input;
        self
    }
    /// <p>An object that contains information on the status of VPC flow logs as a data source.</p>
    pub fn get_flow_logs(&self) -> &::std::option::Option<crate::types::FlowLogsConfigurationResult> {
        &self.flow_logs
    }
    /// <p>An object that contains information on the status of S3 Data event logs as a data source.</p>
    /// This field is required.
    pub fn s3_logs(mut self, input: crate::types::S3LogsConfigurationResult) -> Self {
        self.s3_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information on the status of S3 Data event logs as a data source.</p>
    pub fn set_s3_logs(mut self, input: ::std::option::Option<crate::types::S3LogsConfigurationResult>) -> Self {
        self.s3_logs = input;
        self
    }
    /// <p>An object that contains information on the status of S3 Data event logs as a data source.</p>
    pub fn get_s3_logs(&self) -> &::std::option::Option<crate::types::S3LogsConfigurationResult> {
        &self.s3_logs
    }
    /// <p>An object that contains information on the status of all Kubernetes data sources.</p>
    pub fn kubernetes(mut self, input: crate::types::KubernetesConfigurationResult) -> Self {
        self.kubernetes = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information on the status of all Kubernetes data sources.</p>
    pub fn set_kubernetes(mut self, input: ::std::option::Option<crate::types::KubernetesConfigurationResult>) -> Self {
        self.kubernetes = input;
        self
    }
    /// <p>An object that contains information on the status of all Kubernetes data sources.</p>
    pub fn get_kubernetes(&self) -> &::std::option::Option<crate::types::KubernetesConfigurationResult> {
        &self.kubernetes
    }
    /// <p>Describes the configuration of Malware Protection data sources.</p>
    pub fn malware_protection(mut self, input: crate::types::MalwareProtectionConfigurationResult) -> Self {
        self.malware_protection = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the configuration of Malware Protection data sources.</p>
    pub fn set_malware_protection(mut self, input: ::std::option::Option<crate::types::MalwareProtectionConfigurationResult>) -> Self {
        self.malware_protection = input;
        self
    }
    /// <p>Describes the configuration of Malware Protection data sources.</p>
    pub fn get_malware_protection(&self) -> &::std::option::Option<crate::types::MalwareProtectionConfigurationResult> {
        &self.malware_protection
    }
    /// Consumes the builder and constructs a [`DataSourceConfigurationsResult`](crate::types::DataSourceConfigurationsResult).
    pub fn build(self) -> crate::types::DataSourceConfigurationsResult {
        crate::types::DataSourceConfigurationsResult {
            cloud_trail: self.cloud_trail,
            dns_logs: self.dns_logs,
            flow_logs: self.flow_logs,
            s3_logs: self.s3_logs,
            kubernetes: self.kubernetes,
            malware_protection: self.malware_protection,
        }
    }
}
