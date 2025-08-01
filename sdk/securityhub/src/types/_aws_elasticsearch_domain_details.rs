// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about an Elasticsearch domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsElasticsearchDomainDetails {
    /// <p>IAM policy document specifying the access policies for the new Elasticsearch domain.</p>
    pub access_policies: ::std::option::Option<::std::string::String>,
    /// <p>Additional options for the domain endpoint.</p>
    pub domain_endpoint_options: ::std::option::Option<crate::types::AwsElasticsearchDomainDomainEndpointOptions>,
    /// <p>Unique identifier for an Elasticsearch domain.</p>
    pub domain_id: ::std::option::Option<::std::string::String>,
    /// <p>Name of an Elasticsearch domain.</p>
    /// <p>Domain names are unique across all domains owned by the same account within an Amazon Web Services Region.</p>
    /// <p>Domain names must start with a lowercase letter and must be between 3 and 28 characters.</p>
    /// <p>Valid characters are a-z (lowercase only), 0-9, and – (hyphen).</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>Domain-specific endpoint used to submit index, search, and data upload requests to an Elasticsearch domain.</p>
    /// <p>The endpoint is a service URL.</p>
    pub endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The key-value pair that exists if the Elasticsearch domain uses VPC endpoints.</p>
    pub endpoints: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>OpenSearch version.</p>
    pub elasticsearch_version: ::std::option::Option<::std::string::String>,
    /// <p>Information about an OpenSearch cluster configuration.</p>
    pub elasticsearch_cluster_config: ::std::option::Option<crate::types::AwsElasticsearchDomainElasticsearchClusterConfigDetails>,
    /// <p>Details about the configuration for encryption at rest.</p>
    pub encryption_at_rest_options: ::std::option::Option<crate::types::AwsElasticsearchDomainEncryptionAtRestOptions>,
    /// <p>Configures the CloudWatch Logs to publish for the Elasticsearch domain.</p>
    pub log_publishing_options: ::std::option::Option<crate::types::AwsElasticsearchDomainLogPublishingOptions>,
    /// <p>Details about the configuration for node-to-node encryption.</p>
    pub node_to_node_encryption_options: ::std::option::Option<crate::types::AwsElasticsearchDomainNodeToNodeEncryptionOptions>,
    /// <p>Information about the status of a domain relative to the latest service software.</p>
    pub service_software_options: ::std::option::Option<crate::types::AwsElasticsearchDomainServiceSoftwareOptions>,
    /// <p>Information that OpenSearch derives based on <code>VPCOptions</code> for the domain.</p>
    pub vpc_options: ::std::option::Option<crate::types::AwsElasticsearchDomainVpcOptions>,
}
impl AwsElasticsearchDomainDetails {
    /// <p>IAM policy document specifying the access policies for the new Elasticsearch domain.</p>
    pub fn access_policies(&self) -> ::std::option::Option<&str> {
        self.access_policies.as_deref()
    }
    /// <p>Additional options for the domain endpoint.</p>
    pub fn domain_endpoint_options(&self) -> ::std::option::Option<&crate::types::AwsElasticsearchDomainDomainEndpointOptions> {
        self.domain_endpoint_options.as_ref()
    }
    /// <p>Unique identifier for an Elasticsearch domain.</p>
    pub fn domain_id(&self) -> ::std::option::Option<&str> {
        self.domain_id.as_deref()
    }
    /// <p>Name of an Elasticsearch domain.</p>
    /// <p>Domain names are unique across all domains owned by the same account within an Amazon Web Services Region.</p>
    /// <p>Domain names must start with a lowercase letter and must be between 3 and 28 characters.</p>
    /// <p>Valid characters are a-z (lowercase only), 0-9, and – (hyphen).</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>Domain-specific endpoint used to submit index, search, and data upload requests to an Elasticsearch domain.</p>
    /// <p>The endpoint is a service URL.</p>
    pub fn endpoint(&self) -> ::std::option::Option<&str> {
        self.endpoint.as_deref()
    }
    /// <p>The key-value pair that exists if the Elasticsearch domain uses VPC endpoints.</p>
    pub fn endpoints(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.endpoints.as_ref()
    }
    /// <p>OpenSearch version.</p>
    pub fn elasticsearch_version(&self) -> ::std::option::Option<&str> {
        self.elasticsearch_version.as_deref()
    }
    /// <p>Information about an OpenSearch cluster configuration.</p>
    pub fn elasticsearch_cluster_config(&self) -> ::std::option::Option<&crate::types::AwsElasticsearchDomainElasticsearchClusterConfigDetails> {
        self.elasticsearch_cluster_config.as_ref()
    }
    /// <p>Details about the configuration for encryption at rest.</p>
    pub fn encryption_at_rest_options(&self) -> ::std::option::Option<&crate::types::AwsElasticsearchDomainEncryptionAtRestOptions> {
        self.encryption_at_rest_options.as_ref()
    }
    /// <p>Configures the CloudWatch Logs to publish for the Elasticsearch domain.</p>
    pub fn log_publishing_options(&self) -> ::std::option::Option<&crate::types::AwsElasticsearchDomainLogPublishingOptions> {
        self.log_publishing_options.as_ref()
    }
    /// <p>Details about the configuration for node-to-node encryption.</p>
    pub fn node_to_node_encryption_options(&self) -> ::std::option::Option<&crate::types::AwsElasticsearchDomainNodeToNodeEncryptionOptions> {
        self.node_to_node_encryption_options.as_ref()
    }
    /// <p>Information about the status of a domain relative to the latest service software.</p>
    pub fn service_software_options(&self) -> ::std::option::Option<&crate::types::AwsElasticsearchDomainServiceSoftwareOptions> {
        self.service_software_options.as_ref()
    }
    /// <p>Information that OpenSearch derives based on <code>VPCOptions</code> for the domain.</p>
    pub fn vpc_options(&self) -> ::std::option::Option<&crate::types::AwsElasticsearchDomainVpcOptions> {
        self.vpc_options.as_ref()
    }
}
impl AwsElasticsearchDomainDetails {
    /// Creates a new builder-style object to manufacture [`AwsElasticsearchDomainDetails`](crate::types::AwsElasticsearchDomainDetails).
    pub fn builder() -> crate::types::builders::AwsElasticsearchDomainDetailsBuilder {
        crate::types::builders::AwsElasticsearchDomainDetailsBuilder::default()
    }
}

/// A builder for [`AwsElasticsearchDomainDetails`](crate::types::AwsElasticsearchDomainDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsElasticsearchDomainDetailsBuilder {
    pub(crate) access_policies: ::std::option::Option<::std::string::String>,
    pub(crate) domain_endpoint_options: ::std::option::Option<crate::types::AwsElasticsearchDomainDomainEndpointOptions>,
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) endpoints: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) elasticsearch_version: ::std::option::Option<::std::string::String>,
    pub(crate) elasticsearch_cluster_config: ::std::option::Option<crate::types::AwsElasticsearchDomainElasticsearchClusterConfigDetails>,
    pub(crate) encryption_at_rest_options: ::std::option::Option<crate::types::AwsElasticsearchDomainEncryptionAtRestOptions>,
    pub(crate) log_publishing_options: ::std::option::Option<crate::types::AwsElasticsearchDomainLogPublishingOptions>,
    pub(crate) node_to_node_encryption_options: ::std::option::Option<crate::types::AwsElasticsearchDomainNodeToNodeEncryptionOptions>,
    pub(crate) service_software_options: ::std::option::Option<crate::types::AwsElasticsearchDomainServiceSoftwareOptions>,
    pub(crate) vpc_options: ::std::option::Option<crate::types::AwsElasticsearchDomainVpcOptions>,
}
impl AwsElasticsearchDomainDetailsBuilder {
    /// <p>IAM policy document specifying the access policies for the new Elasticsearch domain.</p>
    pub fn access_policies(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_policies = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>IAM policy document specifying the access policies for the new Elasticsearch domain.</p>
    pub fn set_access_policies(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_policies = input;
        self
    }
    /// <p>IAM policy document specifying the access policies for the new Elasticsearch domain.</p>
    pub fn get_access_policies(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_policies
    }
    /// <p>Additional options for the domain endpoint.</p>
    pub fn domain_endpoint_options(mut self, input: crate::types::AwsElasticsearchDomainDomainEndpointOptions) -> Self {
        self.domain_endpoint_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Additional options for the domain endpoint.</p>
    pub fn set_domain_endpoint_options(mut self, input: ::std::option::Option<crate::types::AwsElasticsearchDomainDomainEndpointOptions>) -> Self {
        self.domain_endpoint_options = input;
        self
    }
    /// <p>Additional options for the domain endpoint.</p>
    pub fn get_domain_endpoint_options(&self) -> &::std::option::Option<crate::types::AwsElasticsearchDomainDomainEndpointOptions> {
        &self.domain_endpoint_options
    }
    /// <p>Unique identifier for an Elasticsearch domain.</p>
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier for an Elasticsearch domain.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>Unique identifier for an Elasticsearch domain.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>Name of an Elasticsearch domain.</p>
    /// <p>Domain names are unique across all domains owned by the same account within an Amazon Web Services Region.</p>
    /// <p>Domain names must start with a lowercase letter and must be between 3 and 28 characters.</p>
    /// <p>Valid characters are a-z (lowercase only), 0-9, and – (hyphen).</p>
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of an Elasticsearch domain.</p>
    /// <p>Domain names are unique across all domains owned by the same account within an Amazon Web Services Region.</p>
    /// <p>Domain names must start with a lowercase letter and must be between 3 and 28 characters.</p>
    /// <p>Valid characters are a-z (lowercase only), 0-9, and – (hyphen).</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>Name of an Elasticsearch domain.</p>
    /// <p>Domain names are unique across all domains owned by the same account within an Amazon Web Services Region.</p>
    /// <p>Domain names must start with a lowercase letter and must be between 3 and 28 characters.</p>
    /// <p>Valid characters are a-z (lowercase only), 0-9, and – (hyphen).</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>Domain-specific endpoint used to submit index, search, and data upload requests to an Elasticsearch domain.</p>
    /// <p>The endpoint is a service URL.</p>
    pub fn endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Domain-specific endpoint used to submit index, search, and data upload requests to an Elasticsearch domain.</p>
    /// <p>The endpoint is a service URL.</p>
    pub fn set_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint = input;
        self
    }
    /// <p>Domain-specific endpoint used to submit index, search, and data upload requests to an Elasticsearch domain.</p>
    /// <p>The endpoint is a service URL.</p>
    pub fn get_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint
    }
    /// Adds a key-value pair to `endpoints`.
    ///
    /// To override the contents of this collection use [`set_endpoints`](Self::set_endpoints).
    ///
    /// <p>The key-value pair that exists if the Elasticsearch domain uses VPC endpoints.</p>
    pub fn endpoints(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.endpoints.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.endpoints = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The key-value pair that exists if the Elasticsearch domain uses VPC endpoints.</p>
    pub fn set_endpoints(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.endpoints = input;
        self
    }
    /// <p>The key-value pair that exists if the Elasticsearch domain uses VPC endpoints.</p>
    pub fn get_endpoints(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.endpoints
    }
    /// <p>OpenSearch version.</p>
    pub fn elasticsearch_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.elasticsearch_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>OpenSearch version.</p>
    pub fn set_elasticsearch_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.elasticsearch_version = input;
        self
    }
    /// <p>OpenSearch version.</p>
    pub fn get_elasticsearch_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.elasticsearch_version
    }
    /// <p>Information about an OpenSearch cluster configuration.</p>
    pub fn elasticsearch_cluster_config(mut self, input: crate::types::AwsElasticsearchDomainElasticsearchClusterConfigDetails) -> Self {
        self.elasticsearch_cluster_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about an OpenSearch cluster configuration.</p>
    pub fn set_elasticsearch_cluster_config(
        mut self,
        input: ::std::option::Option<crate::types::AwsElasticsearchDomainElasticsearchClusterConfigDetails>,
    ) -> Self {
        self.elasticsearch_cluster_config = input;
        self
    }
    /// <p>Information about an OpenSearch cluster configuration.</p>
    pub fn get_elasticsearch_cluster_config(&self) -> &::std::option::Option<crate::types::AwsElasticsearchDomainElasticsearchClusterConfigDetails> {
        &self.elasticsearch_cluster_config
    }
    /// <p>Details about the configuration for encryption at rest.</p>
    pub fn encryption_at_rest_options(mut self, input: crate::types::AwsElasticsearchDomainEncryptionAtRestOptions) -> Self {
        self.encryption_at_rest_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the configuration for encryption at rest.</p>
    pub fn set_encryption_at_rest_options(
        mut self,
        input: ::std::option::Option<crate::types::AwsElasticsearchDomainEncryptionAtRestOptions>,
    ) -> Self {
        self.encryption_at_rest_options = input;
        self
    }
    /// <p>Details about the configuration for encryption at rest.</p>
    pub fn get_encryption_at_rest_options(&self) -> &::std::option::Option<crate::types::AwsElasticsearchDomainEncryptionAtRestOptions> {
        &self.encryption_at_rest_options
    }
    /// <p>Configures the CloudWatch Logs to publish for the Elasticsearch domain.</p>
    pub fn log_publishing_options(mut self, input: crate::types::AwsElasticsearchDomainLogPublishingOptions) -> Self {
        self.log_publishing_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures the CloudWatch Logs to publish for the Elasticsearch domain.</p>
    pub fn set_log_publishing_options(mut self, input: ::std::option::Option<crate::types::AwsElasticsearchDomainLogPublishingOptions>) -> Self {
        self.log_publishing_options = input;
        self
    }
    /// <p>Configures the CloudWatch Logs to publish for the Elasticsearch domain.</p>
    pub fn get_log_publishing_options(&self) -> &::std::option::Option<crate::types::AwsElasticsearchDomainLogPublishingOptions> {
        &self.log_publishing_options
    }
    /// <p>Details about the configuration for node-to-node encryption.</p>
    pub fn node_to_node_encryption_options(mut self, input: crate::types::AwsElasticsearchDomainNodeToNodeEncryptionOptions) -> Self {
        self.node_to_node_encryption_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the configuration for node-to-node encryption.</p>
    pub fn set_node_to_node_encryption_options(
        mut self,
        input: ::std::option::Option<crate::types::AwsElasticsearchDomainNodeToNodeEncryptionOptions>,
    ) -> Self {
        self.node_to_node_encryption_options = input;
        self
    }
    /// <p>Details about the configuration for node-to-node encryption.</p>
    pub fn get_node_to_node_encryption_options(&self) -> &::std::option::Option<crate::types::AwsElasticsearchDomainNodeToNodeEncryptionOptions> {
        &self.node_to_node_encryption_options
    }
    /// <p>Information about the status of a domain relative to the latest service software.</p>
    pub fn service_software_options(mut self, input: crate::types::AwsElasticsearchDomainServiceSoftwareOptions) -> Self {
        self.service_software_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the status of a domain relative to the latest service software.</p>
    pub fn set_service_software_options(mut self, input: ::std::option::Option<crate::types::AwsElasticsearchDomainServiceSoftwareOptions>) -> Self {
        self.service_software_options = input;
        self
    }
    /// <p>Information about the status of a domain relative to the latest service software.</p>
    pub fn get_service_software_options(&self) -> &::std::option::Option<crate::types::AwsElasticsearchDomainServiceSoftwareOptions> {
        &self.service_software_options
    }
    /// <p>Information that OpenSearch derives based on <code>VPCOptions</code> for the domain.</p>
    pub fn vpc_options(mut self, input: crate::types::AwsElasticsearchDomainVpcOptions) -> Self {
        self.vpc_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information that OpenSearch derives based on <code>VPCOptions</code> for the domain.</p>
    pub fn set_vpc_options(mut self, input: ::std::option::Option<crate::types::AwsElasticsearchDomainVpcOptions>) -> Self {
        self.vpc_options = input;
        self
    }
    /// <p>Information that OpenSearch derives based on <code>VPCOptions</code> for the domain.</p>
    pub fn get_vpc_options(&self) -> &::std::option::Option<crate::types::AwsElasticsearchDomainVpcOptions> {
        &self.vpc_options
    }
    /// Consumes the builder and constructs a [`AwsElasticsearchDomainDetails`](crate::types::AwsElasticsearchDomainDetails).
    pub fn build(self) -> crate::types::AwsElasticsearchDomainDetails {
        crate::types::AwsElasticsearchDomainDetails {
            access_policies: self.access_policies,
            domain_endpoint_options: self.domain_endpoint_options,
            domain_id: self.domain_id,
            domain_name: self.domain_name,
            endpoint: self.endpoint,
            endpoints: self.endpoints,
            elasticsearch_version: self.elasticsearch_version,
            elasticsearch_cluster_config: self.elasticsearch_cluster_config,
            encryption_at_rest_options: self.encryption_at_rest_options,
            log_publishing_options: self.log_publishing_options,
            node_to_node_encryption_options: self.node_to_node_encryption_options,
            service_software_options: self.service_software_options,
            vpc_options: self.vpc_options,
        }
    }
}
