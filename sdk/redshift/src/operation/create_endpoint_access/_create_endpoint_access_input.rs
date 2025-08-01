// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEndpointAccessInput {
    /// <p>The cluster identifier of the cluster to access.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID of the owner of the cluster. This is only required if the cluster is in another Amazon Web Services account.</p>
    pub resource_owner: ::std::option::Option<::std::string::String>,
    /// <p>The Redshift-managed VPC endpoint name.</p>
    /// <p>An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    pub endpoint_name: ::std::option::Option<::std::string::String>,
    /// <p>The subnet group from which Amazon Redshift chooses the subnet to deploy the endpoint.</p>
    pub subnet_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    pub vpc_security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateEndpointAccessInput {
    /// <p>The cluster identifier of the cluster to access.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p>The Amazon Web Services account ID of the owner of the cluster. This is only required if the cluster is in another Amazon Web Services account.</p>
    pub fn resource_owner(&self) -> ::std::option::Option<&str> {
        self.resource_owner.as_deref()
    }
    /// <p>The Redshift-managed VPC endpoint name.</p>
    /// <p>An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    pub fn endpoint_name(&self) -> ::std::option::Option<&str> {
        self.endpoint_name.as_deref()
    }
    /// <p>The subnet group from which Amazon Redshift chooses the subnet to deploy the endpoint.</p>
    pub fn subnet_group_name(&self) -> ::std::option::Option<&str> {
        self.subnet_group_name.as_deref()
    }
    /// <p>The security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_security_group_ids.is_none()`.
    pub fn vpc_security_group_ids(&self) -> &[::std::string::String] {
        self.vpc_security_group_ids.as_deref().unwrap_or_default()
    }
}
impl CreateEndpointAccessInput {
    /// Creates a new builder-style object to manufacture [`CreateEndpointAccessInput`](crate::operation::create_endpoint_access::CreateEndpointAccessInput).
    pub fn builder() -> crate::operation::create_endpoint_access::builders::CreateEndpointAccessInputBuilder {
        crate::operation::create_endpoint_access::builders::CreateEndpointAccessInputBuilder::default()
    }
}

/// A builder for [`CreateEndpointAccessInput`](crate::operation::create_endpoint_access::CreateEndpointAccessInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEndpointAccessInputBuilder {
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) resource_owner: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint_name: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateEndpointAccessInputBuilder {
    /// <p>The cluster identifier of the cluster to access.</p>
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cluster identifier of the cluster to access.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The cluster identifier of the cluster to access.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p>The Amazon Web Services account ID of the owner of the cluster. This is only required if the cluster is in another Amazon Web Services account.</p>
    pub fn resource_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the owner of the cluster. This is only required if the cluster is in another Amazon Web Services account.</p>
    pub fn set_resource_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_owner = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the owner of the cluster. This is only required if the cluster is in another Amazon Web Services account.</p>
    pub fn get_resource_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_owner
    }
    /// <p>The Redshift-managed VPC endpoint name.</p>
    /// <p>An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    /// This field is required.
    pub fn endpoint_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Redshift-managed VPC endpoint name.</p>
    /// <p>An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    pub fn set_endpoint_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_name = input;
        self
    }
    /// <p>The Redshift-managed VPC endpoint name.</p>
    /// <p>An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    pub fn get_endpoint_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_name
    }
    /// <p>The subnet group from which Amazon Redshift chooses the subnet to deploy the endpoint.</p>
    /// This field is required.
    pub fn subnet_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subnet group from which Amazon Redshift chooses the subnet to deploy the endpoint.</p>
    pub fn set_subnet_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_group_name = input;
        self
    }
    /// <p>The subnet group from which Amazon Redshift chooses the subnet to deploy the endpoint.</p>
    pub fn get_subnet_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_group_name
    }
    /// Appends an item to `vpc_security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_vpc_security_group_ids`](Self::set_vpc_security_group_ids).
    ///
    /// <p>The security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    pub fn vpc_security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.vpc_security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.vpc_security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    pub fn set_vpc_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.vpc_security_group_ids = input;
        self
    }
    /// <p>The security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    pub fn get_vpc_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.vpc_security_group_ids
    }
    /// Consumes the builder and constructs a [`CreateEndpointAccessInput`](crate::operation::create_endpoint_access::CreateEndpointAccessInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_endpoint_access::CreateEndpointAccessInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_endpoint_access::CreateEndpointAccessInput {
            cluster_identifier: self.cluster_identifier,
            resource_owner: self.resource_owner,
            endpoint_name: self.endpoint_name,
            subnet_group_name: self.subnet_group_name,
            vpc_security_group_ids: self.vpc_security_group_ids,
        })
    }
}
