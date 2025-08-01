// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a Redshift-managed VPC endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEndpointAccessOutput {
    /// <p>The cluster identifier of the cluster associated with the endpoint.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID of the owner of the cluster.</p>
    pub resource_owner: ::std::option::Option<::std::string::String>,
    /// <p>The subnet group name where Amazon Redshift chooses to deploy the endpoint.</p>
    pub subnet_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The status of the endpoint.</p>
    pub endpoint_status: ::std::option::Option<::std::string::String>,
    /// <p>The name of the endpoint.</p>
    pub endpoint_name: ::std::option::Option<::std::string::String>,
    /// <p>The time (UTC) that the endpoint was created.</p>
    pub endpoint_create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The port number on which the cluster accepts incoming connections.</p>
    pub port: ::std::option::Option<i32>,
    /// <p>The DNS address of the endpoint.</p>
    pub address: ::std::option::Option<::std::string::String>,
    /// <p>The security groups associated with the endpoint.</p>
    pub vpc_security_groups: ::std::option::Option<::std::vec::Vec<crate::types::VpcSecurityGroupMembership>>,
    /// <p>The connection endpoint for connecting to an Amazon Redshift cluster through the proxy.</p>
    pub vpc_endpoint: ::std::option::Option<crate::types::VpcEndpoint>,
    _request_id: Option<String>,
}
impl CreateEndpointAccessOutput {
    /// <p>The cluster identifier of the cluster associated with the endpoint.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p>The Amazon Web Services account ID of the owner of the cluster.</p>
    pub fn resource_owner(&self) -> ::std::option::Option<&str> {
        self.resource_owner.as_deref()
    }
    /// <p>The subnet group name where Amazon Redshift chooses to deploy the endpoint.</p>
    pub fn subnet_group_name(&self) -> ::std::option::Option<&str> {
        self.subnet_group_name.as_deref()
    }
    /// <p>The status of the endpoint.</p>
    pub fn endpoint_status(&self) -> ::std::option::Option<&str> {
        self.endpoint_status.as_deref()
    }
    /// <p>The name of the endpoint.</p>
    pub fn endpoint_name(&self) -> ::std::option::Option<&str> {
        self.endpoint_name.as_deref()
    }
    /// <p>The time (UTC) that the endpoint was created.</p>
    pub fn endpoint_create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.endpoint_create_time.as_ref()
    }
    /// <p>The port number on which the cluster accepts incoming connections.</p>
    pub fn port(&self) -> ::std::option::Option<i32> {
        self.port
    }
    /// <p>The DNS address of the endpoint.</p>
    pub fn address(&self) -> ::std::option::Option<&str> {
        self.address.as_deref()
    }
    /// <p>The security groups associated with the endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_security_groups.is_none()`.
    pub fn vpc_security_groups(&self) -> &[crate::types::VpcSecurityGroupMembership] {
        self.vpc_security_groups.as_deref().unwrap_or_default()
    }
    /// <p>The connection endpoint for connecting to an Amazon Redshift cluster through the proxy.</p>
    pub fn vpc_endpoint(&self) -> ::std::option::Option<&crate::types::VpcEndpoint> {
        self.vpc_endpoint.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateEndpointAccessOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateEndpointAccessOutput {
    /// Creates a new builder-style object to manufacture [`CreateEndpointAccessOutput`](crate::operation::create_endpoint_access::CreateEndpointAccessOutput).
    pub fn builder() -> crate::operation::create_endpoint_access::builders::CreateEndpointAccessOutputBuilder {
        crate::operation::create_endpoint_access::builders::CreateEndpointAccessOutputBuilder::default()
    }
}

/// A builder for [`CreateEndpointAccessOutput`](crate::operation::create_endpoint_access::CreateEndpointAccessOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEndpointAccessOutputBuilder {
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) resource_owner: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint_status: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint_name: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint_create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) port: ::std::option::Option<i32>,
    pub(crate) address: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_security_groups: ::std::option::Option<::std::vec::Vec<crate::types::VpcSecurityGroupMembership>>,
    pub(crate) vpc_endpoint: ::std::option::Option<crate::types::VpcEndpoint>,
    _request_id: Option<String>,
}
impl CreateEndpointAccessOutputBuilder {
    /// <p>The cluster identifier of the cluster associated with the endpoint.</p>
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cluster identifier of the cluster associated with the endpoint.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The cluster identifier of the cluster associated with the endpoint.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p>The Amazon Web Services account ID of the owner of the cluster.</p>
    pub fn resource_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the owner of the cluster.</p>
    pub fn set_resource_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_owner = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the owner of the cluster.</p>
    pub fn get_resource_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_owner
    }
    /// <p>The subnet group name where Amazon Redshift chooses to deploy the endpoint.</p>
    pub fn subnet_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subnet group name where Amazon Redshift chooses to deploy the endpoint.</p>
    pub fn set_subnet_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_group_name = input;
        self
    }
    /// <p>The subnet group name where Amazon Redshift chooses to deploy the endpoint.</p>
    pub fn get_subnet_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_group_name
    }
    /// <p>The status of the endpoint.</p>
    pub fn endpoint_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the endpoint.</p>
    pub fn set_endpoint_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_status = input;
        self
    }
    /// <p>The status of the endpoint.</p>
    pub fn get_endpoint_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_status
    }
    /// <p>The name of the endpoint.</p>
    pub fn endpoint_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the endpoint.</p>
    pub fn set_endpoint_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_name = input;
        self
    }
    /// <p>The name of the endpoint.</p>
    pub fn get_endpoint_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_name
    }
    /// <p>The time (UTC) that the endpoint was created.</p>
    pub fn endpoint_create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.endpoint_create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time (UTC) that the endpoint was created.</p>
    pub fn set_endpoint_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.endpoint_create_time = input;
        self
    }
    /// <p>The time (UTC) that the endpoint was created.</p>
    pub fn get_endpoint_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.endpoint_create_time
    }
    /// <p>The port number on which the cluster accepts incoming connections.</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port number on which the cluster accepts incoming connections.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The port number on which the cluster accepts incoming connections.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// <p>The DNS address of the endpoint.</p>
    pub fn address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DNS address of the endpoint.</p>
    pub fn set_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address = input;
        self
    }
    /// <p>The DNS address of the endpoint.</p>
    pub fn get_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.address
    }
    /// Appends an item to `vpc_security_groups`.
    ///
    /// To override the contents of this collection use [`set_vpc_security_groups`](Self::set_vpc_security_groups).
    ///
    /// <p>The security groups associated with the endpoint.</p>
    pub fn vpc_security_groups(mut self, input: crate::types::VpcSecurityGroupMembership) -> Self {
        let mut v = self.vpc_security_groups.unwrap_or_default();
        v.push(input);
        self.vpc_security_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The security groups associated with the endpoint.</p>
    pub fn set_vpc_security_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VpcSecurityGroupMembership>>) -> Self {
        self.vpc_security_groups = input;
        self
    }
    /// <p>The security groups associated with the endpoint.</p>
    pub fn get_vpc_security_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VpcSecurityGroupMembership>> {
        &self.vpc_security_groups
    }
    /// <p>The connection endpoint for connecting to an Amazon Redshift cluster through the proxy.</p>
    pub fn vpc_endpoint(mut self, input: crate::types::VpcEndpoint) -> Self {
        self.vpc_endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>The connection endpoint for connecting to an Amazon Redshift cluster through the proxy.</p>
    pub fn set_vpc_endpoint(mut self, input: ::std::option::Option<crate::types::VpcEndpoint>) -> Self {
        self.vpc_endpoint = input;
        self
    }
    /// <p>The connection endpoint for connecting to an Amazon Redshift cluster through the proxy.</p>
    pub fn get_vpc_endpoint(&self) -> &::std::option::Option<crate::types::VpcEndpoint> {
        &self.vpc_endpoint
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateEndpointAccessOutput`](crate::operation::create_endpoint_access::CreateEndpointAccessOutput).
    pub fn build(self) -> crate::operation::create_endpoint_access::CreateEndpointAccessOutput {
        crate::operation::create_endpoint_access::CreateEndpointAccessOutput {
            cluster_identifier: self.cluster_identifier,
            resource_owner: self.resource_owner,
            subnet_group_name: self.subnet_group_name,
            endpoint_status: self.endpoint_status,
            endpoint_name: self.endpoint_name,
            endpoint_create_time: self.endpoint_create_time,
            port: self.port,
            address: self.address,
            vpc_security_groups: self.vpc_security_groups,
            vpc_endpoint: self.vpc_endpoint,
            _request_id: self._request_id,
        }
    }
}
