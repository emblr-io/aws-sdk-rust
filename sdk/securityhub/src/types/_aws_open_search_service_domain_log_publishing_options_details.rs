// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configures the CloudWatch Logs to publish for the OpenSearch domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsOpenSearchServiceDomainLogPublishingOptionsDetails {
    /// <p>Configures the OpenSearch index logs publishing.</p>
    pub index_slow_logs: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption>,
    /// <p>Configures the OpenSearch search slow log publishing.</p>
    pub search_slow_logs: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption>,
    /// <p>Configures the OpenSearch audit logs publishing.</p>
    pub audit_logs: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption>,
}
impl AwsOpenSearchServiceDomainLogPublishingOptionsDetails {
    /// <p>Configures the OpenSearch index logs publishing.</p>
    pub fn index_slow_logs(&self) -> ::std::option::Option<&crate::types::AwsOpenSearchServiceDomainLogPublishingOption> {
        self.index_slow_logs.as_ref()
    }
    /// <p>Configures the OpenSearch search slow log publishing.</p>
    pub fn search_slow_logs(&self) -> ::std::option::Option<&crate::types::AwsOpenSearchServiceDomainLogPublishingOption> {
        self.search_slow_logs.as_ref()
    }
    /// <p>Configures the OpenSearch audit logs publishing.</p>
    pub fn audit_logs(&self) -> ::std::option::Option<&crate::types::AwsOpenSearchServiceDomainLogPublishingOption> {
        self.audit_logs.as_ref()
    }
}
impl AwsOpenSearchServiceDomainLogPublishingOptionsDetails {
    /// Creates a new builder-style object to manufacture [`AwsOpenSearchServiceDomainLogPublishingOptionsDetails`](crate::types::AwsOpenSearchServiceDomainLogPublishingOptionsDetails).
    pub fn builder() -> crate::types::builders::AwsOpenSearchServiceDomainLogPublishingOptionsDetailsBuilder {
        crate::types::builders::AwsOpenSearchServiceDomainLogPublishingOptionsDetailsBuilder::default()
    }
}

/// A builder for [`AwsOpenSearchServiceDomainLogPublishingOptionsDetails`](crate::types::AwsOpenSearchServiceDomainLogPublishingOptionsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsOpenSearchServiceDomainLogPublishingOptionsDetailsBuilder {
    pub(crate) index_slow_logs: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption>,
    pub(crate) search_slow_logs: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption>,
    pub(crate) audit_logs: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption>,
}
impl AwsOpenSearchServiceDomainLogPublishingOptionsDetailsBuilder {
    /// <p>Configures the OpenSearch index logs publishing.</p>
    pub fn index_slow_logs(mut self, input: crate::types::AwsOpenSearchServiceDomainLogPublishingOption) -> Self {
        self.index_slow_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures the OpenSearch index logs publishing.</p>
    pub fn set_index_slow_logs(mut self, input: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption>) -> Self {
        self.index_slow_logs = input;
        self
    }
    /// <p>Configures the OpenSearch index logs publishing.</p>
    pub fn get_index_slow_logs(&self) -> &::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption> {
        &self.index_slow_logs
    }
    /// <p>Configures the OpenSearch search slow log publishing.</p>
    pub fn search_slow_logs(mut self, input: crate::types::AwsOpenSearchServiceDomainLogPublishingOption) -> Self {
        self.search_slow_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures the OpenSearch search slow log publishing.</p>
    pub fn set_search_slow_logs(mut self, input: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption>) -> Self {
        self.search_slow_logs = input;
        self
    }
    /// <p>Configures the OpenSearch search slow log publishing.</p>
    pub fn get_search_slow_logs(&self) -> &::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption> {
        &self.search_slow_logs
    }
    /// <p>Configures the OpenSearch audit logs publishing.</p>
    pub fn audit_logs(mut self, input: crate::types::AwsOpenSearchServiceDomainLogPublishingOption) -> Self {
        self.audit_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures the OpenSearch audit logs publishing.</p>
    pub fn set_audit_logs(mut self, input: ::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption>) -> Self {
        self.audit_logs = input;
        self
    }
    /// <p>Configures the OpenSearch audit logs publishing.</p>
    pub fn get_audit_logs(&self) -> &::std::option::Option<crate::types::AwsOpenSearchServiceDomainLogPublishingOption> {
        &self.audit_logs
    }
    /// Consumes the builder and constructs a [`AwsOpenSearchServiceDomainLogPublishingOptionsDetails`](crate::types::AwsOpenSearchServiceDomainLogPublishingOptionsDetails).
    pub fn build(self) -> crate::types::AwsOpenSearchServiceDomainLogPublishingOptionsDetails {
        crate::types::AwsOpenSearchServiceDomainLogPublishingOptionsDetails {
            index_slow_logs: self.index_slow_logs,
            search_slow_logs: self.search_slow_logs,
            audit_logs: self.audit_logs,
        }
    }
}
