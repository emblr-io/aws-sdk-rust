// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateClusterV2Input {
    /// <p>The name of the cluster.</p>
    pub cluster_name: ::std::option::Option<::std::string::String>,
    /// <p>A map of tags that you want the cluster to have.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Information about the provisioned cluster.</p>
    pub provisioned: ::std::option::Option<crate::types::ProvisionedRequest>,
    /// <p>Information about the serverless cluster.</p>
    pub serverless: ::std::option::Option<crate::types::ServerlessRequest>,
}
impl CreateClusterV2Input {
    /// <p>The name of the cluster.</p>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
    /// <p>A map of tags that you want the cluster to have.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>Information about the provisioned cluster.</p>
    pub fn provisioned(&self) -> ::std::option::Option<&crate::types::ProvisionedRequest> {
        self.provisioned.as_ref()
    }
    /// <p>Information about the serverless cluster.</p>
    pub fn serverless(&self) -> ::std::option::Option<&crate::types::ServerlessRequest> {
        self.serverless.as_ref()
    }
}
impl CreateClusterV2Input {
    /// Creates a new builder-style object to manufacture [`CreateClusterV2Input`](crate::operation::create_cluster_v2::CreateClusterV2Input).
    pub fn builder() -> crate::operation::create_cluster_v2::builders::CreateClusterV2InputBuilder {
        crate::operation::create_cluster_v2::builders::CreateClusterV2InputBuilder::default()
    }
}

/// A builder for [`CreateClusterV2Input`](crate::operation::create_cluster_v2::CreateClusterV2Input).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateClusterV2InputBuilder {
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) provisioned: ::std::option::Option<crate::types::ProvisionedRequest>,
    pub(crate) serverless: ::std::option::Option<crate::types::ServerlessRequest>,
}
impl CreateClusterV2InputBuilder {
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
    /// <p>A map of tags that you want the cluster to have.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of tags that you want the cluster to have.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map of tags that you want the cluster to have.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>Information about the provisioned cluster.</p>
    pub fn provisioned(mut self, input: crate::types::ProvisionedRequest) -> Self {
        self.provisioned = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the provisioned cluster.</p>
    pub fn set_provisioned(mut self, input: ::std::option::Option<crate::types::ProvisionedRequest>) -> Self {
        self.provisioned = input;
        self
    }
    /// <p>Information about the provisioned cluster.</p>
    pub fn get_provisioned(&self) -> &::std::option::Option<crate::types::ProvisionedRequest> {
        &self.provisioned
    }
    /// <p>Information about the serverless cluster.</p>
    pub fn serverless(mut self, input: crate::types::ServerlessRequest) -> Self {
        self.serverless = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the serverless cluster.</p>
    pub fn set_serverless(mut self, input: ::std::option::Option<crate::types::ServerlessRequest>) -> Self {
        self.serverless = input;
        self
    }
    /// <p>Information about the serverless cluster.</p>
    pub fn get_serverless(&self) -> &::std::option::Option<crate::types::ServerlessRequest> {
        &self.serverless
    }
    /// Consumes the builder and constructs a [`CreateClusterV2Input`](crate::operation::create_cluster_v2::CreateClusterV2Input).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_cluster_v2::CreateClusterV2Input, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_cluster_v2::CreateClusterV2Input {
            cluster_name: self.cluster_name,
            tags: self.tags,
            provisioned: self.provisioned,
            serverless: self.serverless,
        })
    }
}
