// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The client authentication information used in order to authenticate with the Apache Kafka cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KafkaClusterClientAuthenticationDescription {
    /// <p>The type of client authentication used to connect to the Apache Kafka cluster. Value NONE means that no client authentication is used.</p>
    pub authentication_type: ::std::option::Option<crate::types::KafkaClusterClientAuthenticationType>,
}
impl KafkaClusterClientAuthenticationDescription {
    /// <p>The type of client authentication used to connect to the Apache Kafka cluster. Value NONE means that no client authentication is used.</p>
    pub fn authentication_type(&self) -> ::std::option::Option<&crate::types::KafkaClusterClientAuthenticationType> {
        self.authentication_type.as_ref()
    }
}
impl KafkaClusterClientAuthenticationDescription {
    /// Creates a new builder-style object to manufacture [`KafkaClusterClientAuthenticationDescription`](crate::types::KafkaClusterClientAuthenticationDescription).
    pub fn builder() -> crate::types::builders::KafkaClusterClientAuthenticationDescriptionBuilder {
        crate::types::builders::KafkaClusterClientAuthenticationDescriptionBuilder::default()
    }
}

/// A builder for [`KafkaClusterClientAuthenticationDescription`](crate::types::KafkaClusterClientAuthenticationDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KafkaClusterClientAuthenticationDescriptionBuilder {
    pub(crate) authentication_type: ::std::option::Option<crate::types::KafkaClusterClientAuthenticationType>,
}
impl KafkaClusterClientAuthenticationDescriptionBuilder {
    /// <p>The type of client authentication used to connect to the Apache Kafka cluster. Value NONE means that no client authentication is used.</p>
    pub fn authentication_type(mut self, input: crate::types::KafkaClusterClientAuthenticationType) -> Self {
        self.authentication_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of client authentication used to connect to the Apache Kafka cluster. Value NONE means that no client authentication is used.</p>
    pub fn set_authentication_type(mut self, input: ::std::option::Option<crate::types::KafkaClusterClientAuthenticationType>) -> Self {
        self.authentication_type = input;
        self
    }
    /// <p>The type of client authentication used to connect to the Apache Kafka cluster. Value NONE means that no client authentication is used.</p>
    pub fn get_authentication_type(&self) -> &::std::option::Option<crate::types::KafkaClusterClientAuthenticationType> {
        &self.authentication_type
    }
    /// Consumes the builder and constructs a [`KafkaClusterClientAuthenticationDescription`](crate::types::KafkaClusterClientAuthenticationDescription).
    pub fn build(self) -> crate::types::KafkaClusterClientAuthenticationDescription {
        crate::types::KafkaClusterClientAuthenticationDescription {
            authentication_type: self.authentication_type,
        }
    }
}
