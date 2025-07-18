// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This structure contains information about the OpenSearch Service data access policy used for this integration. The access policy defines the access controls for the collection. This data access policy was automatically created as part of the integration setup. For more information about OpenSearch Service data access policies, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-data-access.html">Data access control for Amazon OpenSearch Serverless</a> in the OpenSearch Service Developer Guide.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OpenSearchDataAccessPolicy {
    /// <p>The name of the data access policy.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub status: ::std::option::Option<crate::types::OpenSearchResourceStatus>,
}
impl OpenSearchDataAccessPolicy {
    /// <p>The name of the data access policy.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::OpenSearchResourceStatus> {
        self.status.as_ref()
    }
}
impl OpenSearchDataAccessPolicy {
    /// Creates a new builder-style object to manufacture [`OpenSearchDataAccessPolicy`](crate::types::OpenSearchDataAccessPolicy).
    pub fn builder() -> crate::types::builders::OpenSearchDataAccessPolicyBuilder {
        crate::types::builders::OpenSearchDataAccessPolicyBuilder::default()
    }
}

/// A builder for [`OpenSearchDataAccessPolicy`](crate::types::OpenSearchDataAccessPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OpenSearchDataAccessPolicyBuilder {
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::OpenSearchResourceStatus>,
}
impl OpenSearchDataAccessPolicyBuilder {
    /// <p>The name of the data access policy.</p>
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data access policy.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>The name of the data access policy.</p>
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
    /// Consumes the builder and constructs a [`OpenSearchDataAccessPolicy`](crate::types::OpenSearchDataAccessPolicy).
    pub fn build(self) -> crate::types::OpenSearchDataAccessPolicy {
        crate::types::OpenSearchDataAccessPolicy {
            policy_name: self.policy_name,
            status: self.status,
        }
    }
}
