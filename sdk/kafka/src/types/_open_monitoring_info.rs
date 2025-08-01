// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>JMX and Node monitoring for the MSK cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OpenMonitoringInfo {
    /// <p>Prometheus settings.</p>
    pub prometheus: ::std::option::Option<crate::types::PrometheusInfo>,
}
impl OpenMonitoringInfo {
    /// <p>Prometheus settings.</p>
    pub fn prometheus(&self) -> ::std::option::Option<&crate::types::PrometheusInfo> {
        self.prometheus.as_ref()
    }
}
impl OpenMonitoringInfo {
    /// Creates a new builder-style object to manufacture [`OpenMonitoringInfo`](crate::types::OpenMonitoringInfo).
    pub fn builder() -> crate::types::builders::OpenMonitoringInfoBuilder {
        crate::types::builders::OpenMonitoringInfoBuilder::default()
    }
}

/// A builder for [`OpenMonitoringInfo`](crate::types::OpenMonitoringInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OpenMonitoringInfoBuilder {
    pub(crate) prometheus: ::std::option::Option<crate::types::PrometheusInfo>,
}
impl OpenMonitoringInfoBuilder {
    /// <p>Prometheus settings.</p>
    /// This field is required.
    pub fn prometheus(mut self, input: crate::types::PrometheusInfo) -> Self {
        self.prometheus = ::std::option::Option::Some(input);
        self
    }
    /// <p>Prometheus settings.</p>
    pub fn set_prometheus(mut self, input: ::std::option::Option<crate::types::PrometheusInfo>) -> Self {
        self.prometheus = input;
        self
    }
    /// <p>Prometheus settings.</p>
    pub fn get_prometheus(&self) -> &::std::option::Option<crate::types::PrometheusInfo> {
        &self.prometheus
    }
    /// Consumes the builder and constructs a [`OpenMonitoringInfo`](crate::types::OpenMonitoringInfo).
    pub fn build(self) -> crate::types::OpenMonitoringInfo {
        crate::types::OpenMonitoringInfo { prometheus: self.prometheus }
    }
}
