// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateVpcConnectionInput {
    /// <p>The cluster Amazon Resource Name (ARN) for the VPC connection.</p>
    pub target_cluster_arn: ::std::option::Option<::std::string::String>,
    /// <p>The authentication type of VPC connection.</p>
    pub authentication: ::std::option::Option<::std::string::String>,
    /// <p>The VPC ID of VPC connection.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>The list of client subnets.</p>
    pub client_subnets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The list of security groups.</p>
    pub security_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A map of tags for the VPC connection.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateVpcConnectionInput {
    /// <p>The cluster Amazon Resource Name (ARN) for the VPC connection.</p>
    pub fn target_cluster_arn(&self) -> ::std::option::Option<&str> {
        self.target_cluster_arn.as_deref()
    }
    /// <p>The authentication type of VPC connection.</p>
    pub fn authentication(&self) -> ::std::option::Option<&str> {
        self.authentication.as_deref()
    }
    /// <p>The VPC ID of VPC connection.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>The list of client subnets.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.client_subnets.is_none()`.
    pub fn client_subnets(&self) -> &[::std::string::String] {
        self.client_subnets.as_deref().unwrap_or_default()
    }
    /// <p>The list of security groups.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_groups.is_none()`.
    pub fn security_groups(&self) -> &[::std::string::String] {
        self.security_groups.as_deref().unwrap_or_default()
    }
    /// <p>A map of tags for the VPC connection.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateVpcConnectionInput {
    /// Creates a new builder-style object to manufacture [`CreateVpcConnectionInput`](crate::operation::create_vpc_connection::CreateVpcConnectionInput).
    pub fn builder() -> crate::operation::create_vpc_connection::builders::CreateVpcConnectionInputBuilder {
        crate::operation::create_vpc_connection::builders::CreateVpcConnectionInputBuilder::default()
    }
}

/// A builder for [`CreateVpcConnectionInput`](crate::operation::create_vpc_connection::CreateVpcConnectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateVpcConnectionInputBuilder {
    pub(crate) target_cluster_arn: ::std::option::Option<::std::string::String>,
    pub(crate) authentication: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_subnets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) security_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateVpcConnectionInputBuilder {
    /// <p>The cluster Amazon Resource Name (ARN) for the VPC connection.</p>
    /// This field is required.
    pub fn target_cluster_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_cluster_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cluster Amazon Resource Name (ARN) for the VPC connection.</p>
    pub fn set_target_cluster_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_cluster_arn = input;
        self
    }
    /// <p>The cluster Amazon Resource Name (ARN) for the VPC connection.</p>
    pub fn get_target_cluster_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_cluster_arn
    }
    /// <p>The authentication type of VPC connection.</p>
    /// This field is required.
    pub fn authentication(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authentication = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The authentication type of VPC connection.</p>
    pub fn set_authentication(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authentication = input;
        self
    }
    /// <p>The authentication type of VPC connection.</p>
    pub fn get_authentication(&self) -> &::std::option::Option<::std::string::String> {
        &self.authentication
    }
    /// <p>The VPC ID of VPC connection.</p>
    /// This field is required.
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The VPC ID of VPC connection.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The VPC ID of VPC connection.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// Appends an item to `client_subnets`.
    ///
    /// To override the contents of this collection use [`set_client_subnets`](Self::set_client_subnets).
    ///
    /// <p>The list of client subnets.</p>
    pub fn client_subnets(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.client_subnets.unwrap_or_default();
        v.push(input.into());
        self.client_subnets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of client subnets.</p>
    pub fn set_client_subnets(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.client_subnets = input;
        self
    }
    /// <p>The list of client subnets.</p>
    pub fn get_client_subnets(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.client_subnets
    }
    /// Appends an item to `security_groups`.
    ///
    /// To override the contents of this collection use [`set_security_groups`](Self::set_security_groups).
    ///
    /// <p>The list of security groups.</p>
    pub fn security_groups(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_groups.unwrap_or_default();
        v.push(input.into());
        self.security_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of security groups.</p>
    pub fn set_security_groups(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_groups = input;
        self
    }
    /// <p>The list of security groups.</p>
    pub fn get_security_groups(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_groups
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A map of tags for the VPC connection.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of tags for the VPC connection.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map of tags for the VPC connection.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateVpcConnectionInput`](crate::operation::create_vpc_connection::CreateVpcConnectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_vpc_connection::CreateVpcConnectionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_vpc_connection::CreateVpcConnectionInput {
            target_cluster_arn: self.target_cluster_arn,
            authentication: self.authentication,
            vpc_id: self.vpc_id,
            client_subnets: self.client_subnets,
            security_groups: self.security_groups,
            tags: self.tags,
        })
    }
}
