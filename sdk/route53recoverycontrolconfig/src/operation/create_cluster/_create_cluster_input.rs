// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Creates a cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateClusterInput {
    /// <p>A unique, case-sensitive string of up to 64 ASCII characters. To make an idempotent API request with an action, specify a client token in the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The name of the cluster.</p>
    pub cluster_name: ::std::option::Option<::std::string::String>,
    /// <p>The tags associated with the cluster.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The network type of the cluster. NetworkType can be one of the following: IPV4, DUALSTACK.</p>
    pub network_type: ::std::option::Option<crate::types::NetworkType>,
}
impl CreateClusterInput {
    /// <p>A unique, case-sensitive string of up to 64 ASCII characters. To make an idempotent API request with an action, specify a client token in the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The name of the cluster.</p>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
    /// <p>The tags associated with the cluster.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The network type of the cluster. NetworkType can be one of the following: IPV4, DUALSTACK.</p>
    pub fn network_type(&self) -> ::std::option::Option<&crate::types::NetworkType> {
        self.network_type.as_ref()
    }
}
impl CreateClusterInput {
    /// Creates a new builder-style object to manufacture [`CreateClusterInput`](crate::operation::create_cluster::CreateClusterInput).
    pub fn builder() -> crate::operation::create_cluster::builders::CreateClusterInputBuilder {
        crate::operation::create_cluster::builders::CreateClusterInputBuilder::default()
    }
}

/// A builder for [`CreateClusterInput`](crate::operation::create_cluster::CreateClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateClusterInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) network_type: ::std::option::Option<crate::types::NetworkType>,
}
impl CreateClusterInputBuilder {
    /// <p>A unique, case-sensitive string of up to 64 ASCII characters. To make an idempotent API request with an action, specify a client token in the request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive string of up to 64 ASCII characters. To make an idempotent API request with an action, specify a client token in the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive string of up to 64 ASCII characters. To make an idempotent API request with an action, specify a client token in the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The name of the cluster.</p>
    /// This field is required.
    pub fn cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster.</p>
    pub fn set_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_name = input;
        self
    }
    /// <p>The name of the cluster.</p>
    pub fn get_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_name
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags associated with the cluster.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags associated with the cluster.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags associated with the cluster.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The network type of the cluster. NetworkType can be one of the following: IPV4, DUALSTACK.</p>
    pub fn network_type(mut self, input: crate::types::NetworkType) -> Self {
        self.network_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The network type of the cluster. NetworkType can be one of the following: IPV4, DUALSTACK.</p>
    pub fn set_network_type(mut self, input: ::std::option::Option<crate::types::NetworkType>) -> Self {
        self.network_type = input;
        self
    }
    /// <p>The network type of the cluster. NetworkType can be one of the following: IPV4, DUALSTACK.</p>
    pub fn get_network_type(&self) -> &::std::option::Option<crate::types::NetworkType> {
        &self.network_type
    }
    /// Consumes the builder and constructs a [`CreateClusterInput`](crate::operation::create_cluster::CreateClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_cluster::CreateClusterInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_cluster::CreateClusterInput {
            client_token: self.client_token,
            cluster_name: self.cluster_name,
            tags: self.tags,
            network_type: self.network_type,
        })
    }
}
