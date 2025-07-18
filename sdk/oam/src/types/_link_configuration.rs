// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Use this structure to optionally create filters that specify that only some metric namespaces or log groups are to be shared from the source account to the monitoring account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LinkConfiguration {
    /// <p>Use this structure to filter which log groups are to send log events from the source account to the monitoring account.</p>
    pub log_group_configuration: ::std::option::Option<crate::types::LogGroupConfiguration>,
    /// <p>Use this structure to filter which metric namespaces are to be shared from the source account to the monitoring account.</p>
    pub metric_configuration: ::std::option::Option<crate::types::MetricConfiguration>,
}
impl LinkConfiguration {
    /// <p>Use this structure to filter which log groups are to send log events from the source account to the monitoring account.</p>
    pub fn log_group_configuration(&self) -> ::std::option::Option<&crate::types::LogGroupConfiguration> {
        self.log_group_configuration.as_ref()
    }
    /// <p>Use this structure to filter which metric namespaces are to be shared from the source account to the monitoring account.</p>
    pub fn metric_configuration(&self) -> ::std::option::Option<&crate::types::MetricConfiguration> {
        self.metric_configuration.as_ref()
    }
}
impl LinkConfiguration {
    /// Creates a new builder-style object to manufacture [`LinkConfiguration`](crate::types::LinkConfiguration).
    pub fn builder() -> crate::types::builders::LinkConfigurationBuilder {
        crate::types::builders::LinkConfigurationBuilder::default()
    }
}

/// A builder for [`LinkConfiguration`](crate::types::LinkConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LinkConfigurationBuilder {
    pub(crate) log_group_configuration: ::std::option::Option<crate::types::LogGroupConfiguration>,
    pub(crate) metric_configuration: ::std::option::Option<crate::types::MetricConfiguration>,
}
impl LinkConfigurationBuilder {
    /// <p>Use this structure to filter which log groups are to send log events from the source account to the monitoring account.</p>
    pub fn log_group_configuration(mut self, input: crate::types::LogGroupConfiguration) -> Self {
        self.log_group_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this structure to filter which log groups are to send log events from the source account to the monitoring account.</p>
    pub fn set_log_group_configuration(mut self, input: ::std::option::Option<crate::types::LogGroupConfiguration>) -> Self {
        self.log_group_configuration = input;
        self
    }
    /// <p>Use this structure to filter which log groups are to send log events from the source account to the monitoring account.</p>
    pub fn get_log_group_configuration(&self) -> &::std::option::Option<crate::types::LogGroupConfiguration> {
        &self.log_group_configuration
    }
    /// <p>Use this structure to filter which metric namespaces are to be shared from the source account to the monitoring account.</p>
    pub fn metric_configuration(mut self, input: crate::types::MetricConfiguration) -> Self {
        self.metric_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this structure to filter which metric namespaces are to be shared from the source account to the monitoring account.</p>
    pub fn set_metric_configuration(mut self, input: ::std::option::Option<crate::types::MetricConfiguration>) -> Self {
        self.metric_configuration = input;
        self
    }
    /// <p>Use this structure to filter which metric namespaces are to be shared from the source account to the monitoring account.</p>
    pub fn get_metric_configuration(&self) -> &::std::option::Option<crate::types::MetricConfiguration> {
        &self.metric_configuration
    }
    /// Consumes the builder and constructs a [`LinkConfiguration`](crate::types::LinkConfiguration).
    pub fn build(self) -> crate::types::LinkConfiguration {
        crate::types::LinkConfiguration {
            log_group_configuration: self.log_group_configuration,
            metric_configuration: self.metric_configuration,
        }
    }
}
