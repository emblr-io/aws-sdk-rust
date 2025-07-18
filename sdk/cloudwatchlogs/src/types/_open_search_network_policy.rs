// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This structure contains information about the OpenSearch Service network policy used for this integration. The network policy assigns network access settings to collections. For more information, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html#serverless-network-policies">Network policies</a> in the OpenSearch Service Developer Guide.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OpenSearchNetworkPolicy {
    /// <p>The name of the network policy.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub status: ::std::option::Option<crate::types::OpenSearchResourceStatus>,
}
impl OpenSearchNetworkPolicy {
    /// <p>The name of the network policy.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::OpenSearchResourceStatus> {
        self.status.as_ref()
    }
}
impl OpenSearchNetworkPolicy {
    /// Creates a new builder-style object to manufacture [`OpenSearchNetworkPolicy`](crate::types::OpenSearchNetworkPolicy).
    pub fn builder() -> crate::types::builders::OpenSearchNetworkPolicyBuilder {
        crate::types::builders::OpenSearchNetworkPolicyBuilder::default()
    }
}

/// A builder for [`OpenSearchNetworkPolicy`](crate::types::OpenSearchNetworkPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OpenSearchNetworkPolicyBuilder {
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::OpenSearchResourceStatus>,
}
impl OpenSearchNetworkPolicyBuilder {
    /// <p>The name of the network policy.</p>
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the network policy.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>The name of the network policy.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn status(mut self, input: crate::types::OpenSearchResourceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::OpenSearchResourceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::OpenSearchResourceStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`OpenSearchNetworkPolicy`](crate::types::OpenSearchNetworkPolicy).
    pub fn build(self) -> crate::types::OpenSearchNetworkPolicy {
        crate::types::OpenSearchNetworkPolicy {
            policy_name: self.policy_name,
            status: self.status,
        }
    }
}
