// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The description of the Apache Kafka cluster to which the connector is connected.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApacheKafkaClusterDescription {
    /// <p>The bootstrap servers of the cluster.</p>
    pub bootstrap_servers: ::std::option::Option<::std::string::String>,
    /// <p>Details of an Amazon VPC which has network connectivity to the Apache Kafka cluster.</p>
    pub vpc: ::std::option::Option<crate::types::VpcDescription>,
}
impl ApacheKafkaClusterDescription {
    /// <p>The bootstrap servers of the cluster.</p>
    pub fn bootstrap_servers(&self) -> ::std::option::Option<&str> {
        self.bootstrap_servers.as_deref()
    }
    /// <p>Details of an Amazon VPC which has network connectivity to the Apache Kafka cluster.</p>
    pub fn vpc(&self) -> ::std::option::Option<&crate::types::VpcDescription> {
        self.vpc.as_ref()
    }
}
impl ApacheKafkaClusterDescription {
    /// Creates a new builder-style object to manufacture [`ApacheKafkaClusterDescription`](crate::types::ApacheKafkaClusterDescription).
    pub fn builder() -> crate::types::builders::ApacheKafkaClusterDescriptionBuilder {
        crate::types::builders::ApacheKafkaClusterDescriptionBuilder::default()
    }
}

/// A builder for [`ApacheKafkaClusterDescription`](crate::types::ApacheKafkaClusterDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApacheKafkaClusterDescriptionBuilder {
    pub(crate) bootstrap_servers: ::std::option::Option<::std::string::String>,
    pub(crate) vpc: ::std::option::Option<crate::types::VpcDescription>,
}
impl ApacheKafkaClusterDescriptionBuilder {
    /// <p>The bootstrap servers of the cluster.</p>
    pub fn bootstrap_servers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bootstrap_servers = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The bootstrap servers of the cluster.</p>
    pub fn set_bootstrap_servers(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bootstrap_servers = input;
        self
    }
    /// <p>The bootstrap servers of the cluster.</p>
    pub fn get_bootstrap_servers(&self) -> &::std::option::Option<::std::string::String> {
        &self.bootstrap_servers
    }
    /// <p>Details of an Amazon VPC which has network connectivity to the Apache Kafka cluster.</p>
    pub fn vpc(mut self, input: crate::types::VpcDescription) -> Self {
        self.vpc = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details of an Amazon VPC which has network connectivity to the Apache Kafka cluster.</p>
    pub fn set_vpc(mut self, input: ::std::option::Option<crate::types::VpcDescription>) -> Self {
        self.vpc = input;
        self
    }
    /// <p>Details of an Amazon VPC which has network connectivity to the Apache Kafka cluster.</p>
    pub fn get_vpc(&self) -> &::std::option::Option<crate::types::VpcDescription> {
        &self.vpc
    }
    /// Consumes the builder and constructs a [`ApacheKafkaClusterDescription`](crate::types::ApacheKafkaClusterDescription).
    pub fn build(self) -> crate::types::ApacheKafkaClusterDescription {
        crate::types::ApacheKafkaClusterDescription {
            bootstrap_servers: self.bootstrap_servers,
            vpc: self.vpc,
        }
    }
}
