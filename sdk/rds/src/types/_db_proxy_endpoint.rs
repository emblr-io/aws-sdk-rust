// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The data structure representing an endpoint associated with a DB proxy. RDS automatically creates one endpoint for each DB proxy. For Aurora DB clusters, you can associate additional endpoints with the same DB proxy. These endpoints can be read/write or read-only. They can also reside in different VPCs than the associated DB proxy.</p>
/// <p>This data type is used as a response element in the <code>DescribeDBProxyEndpoints</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DbProxyEndpoint {
    /// <p>The name for the DB proxy endpoint. An identifier must begin with a letter and must contain only ASCII letters, digits, and hyphens; it can't end with a hyphen or contain two consecutive hyphens.</p>
    pub db_proxy_endpoint_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for the DB proxy endpoint.</p>
    pub db_proxy_endpoint_arn: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the DB proxy that is associated with this DB proxy endpoint.</p>
    pub db_proxy_name: ::std::option::Option<::std::string::String>,
    /// <p>The current status of this DB proxy endpoint. A status of <code>available</code> means the endpoint is ready to handle requests. Other values indicate that you must wait for the endpoint to be ready, or take some action to resolve an issue.</p>
    pub status: ::std::option::Option<crate::types::DbProxyEndpointStatus>,
    /// <p>Provides the VPC ID of the DB proxy endpoint.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>Provides a list of VPC security groups that the DB proxy endpoint belongs to.</p>
    pub vpc_security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The EC2 subnet IDs for the DB proxy endpoint.</p>
    pub vpc_subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The endpoint that you can use to connect to the DB proxy. You include the endpoint value in the connection string for a database client application.</p>
    pub endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The date and time when the DB proxy endpoint was first created.</p>
    pub created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A value that indicates whether the DB proxy endpoint can be used for read/write or read-only operations.</p>
    pub target_role: ::std::option::Option<crate::types::DbProxyEndpointTargetRole>,
    /// <p>Indicates whether this endpoint is the default endpoint for the associated DB proxy. Default DB proxy endpoints always have read/write capability. Other endpoints that you associate with the DB proxy can be either read/write or read-only.</p>
    pub is_default: ::std::option::Option<bool>,
}
impl DbProxyEndpoint {
    /// <p>The name for the DB proxy endpoint. An identifier must begin with a letter and must contain only ASCII letters, digits, and hyphens; it can't end with a hyphen or contain two consecutive hyphens.</p>
    pub fn db_proxy_endpoint_name(&self) -> ::std::option::Option<&str> {
        self.db_proxy_endpoint_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for the DB proxy endpoint.</p>
    pub fn db_proxy_endpoint_arn(&self) -> ::std::option::Option<&str> {
        self.db_proxy_endpoint_arn.as_deref()
    }
    /// <p>The identifier for the DB proxy that is associated with this DB proxy endpoint.</p>
    pub fn db_proxy_name(&self) -> ::std::option::Option<&str> {
        self.db_proxy_name.as_deref()
    }
    /// <p>The current status of this DB proxy endpoint. A status of <code>available</code> means the endpoint is ready to handle requests. Other values indicate that you must wait for the endpoint to be ready, or take some action to resolve an issue.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DbProxyEndpointStatus> {
        self.status.as_ref()
    }
    /// <p>Provides the VPC ID of the DB proxy endpoint.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>Provides a list of VPC security groups that the DB proxy endpoint belongs to.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_security_group_ids.is_none()`.
    pub fn vpc_security_group_ids(&self) -> &[::std::string::String] {
        self.vpc_security_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>The EC2 subnet IDs for the DB proxy endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_subnet_ids.is_none()`.
    pub fn vpc_subnet_ids(&self) -> &[::std::string::String] {
        self.vpc_subnet_ids.as_deref().unwrap_or_default()
    }
    /// <p>The endpoint that you can use to connect to the DB proxy. You include the endpoint value in the connection string for a database client application.</p>
    pub fn endpoint(&self) -> ::std::option::Option<&str> {
        self.endpoint.as_deref()
    }
    /// <p>The date and time when the DB proxy endpoint was first created.</p>
    pub fn created_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_date.as_ref()
    }
    /// <p>A value that indicates whether the DB proxy endpoint can be used for read/write or read-only operations.</p>
    pub fn target_role(&self) -> ::std::option::Option<&crate::types::DbProxyEndpointTargetRole> {
        self.target_role.as_ref()
    }
    /// <p>Indicates whether this endpoint is the default endpoint for the associated DB proxy. Default DB proxy endpoints always have read/write capability. Other endpoints that you associate with the DB proxy can be either read/write or read-only.</p>
    pub fn is_default(&self) -> ::std::option::Option<bool> {
        self.is_default
    }
}
impl DbProxyEndpoint {
    /// Creates a new builder-style object to manufacture [`DbProxyEndpoint`](crate::types::DbProxyEndpoint).
    pub fn builder() -> crate::types::builders::DbProxyEndpointBuilder {
        crate::types::builders::DbProxyEndpointBuilder::default()
    }
}

/// A builder for [`DbProxyEndpoint`](crate::types::DbProxyEndpoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DbProxyEndpointBuilder {
    pub(crate) db_proxy_endpoint_name: ::std::option::Option<::std::string::String>,
    pub(crate) db_proxy_endpoint_arn: ::std::option::Option<::std::string::String>,
    pub(crate) db_proxy_name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::DbProxyEndpointStatus>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) vpc_subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) target_role: ::std::option::Option<crate::types::DbProxyEndpointTargetRole>,
    pub(crate) is_default: ::std::option::Option<bool>,
}
impl DbProxyEndpointBuilder {
    /// <p>The name for the DB proxy endpoint. An identifier must begin with a letter and must contain only ASCII letters, digits, and hyphens; it can't end with a hyphen or contain two consecutive hyphens.</p>
    pub fn db_proxy_endpoint_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_proxy_endpoint_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the DB proxy endpoint. An identifier must begin with a letter and must contain only ASCII letters, digits, and hyphens; it can't end with a hyphen or contain two consecutive hyphens.</p>
    pub fn set_db_proxy_endpoint_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_proxy_endpoint_name = input;
        self
    }
    /// <p>The name for the DB proxy endpoint. An identifier must begin with a letter and must contain only ASCII letters, digits, and hyphens; it can't end with a hyphen or contain two consecutive hyphens.</p>
    pub fn get_db_proxy_endpoint_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_proxy_endpoint_name
    }
    /// <p>The Amazon Resource Name (ARN) for the DB proxy endpoint.</p>
    pub fn db_proxy_endpoint_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_proxy_endpoint_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the DB proxy endpoint.</p>
    pub fn set_db_proxy_endpoint_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_proxy_endpoint_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the DB proxy endpoint.</p>
    pub fn get_db_proxy_endpoint_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_proxy_endpoint_arn
    }
    /// <p>The identifier for the DB proxy that is associated with this DB proxy endpoint.</p>
    pub fn db_proxy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_proxy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the DB proxy that is associated with this DB proxy endpoint.</p>
    pub fn set_db_proxy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_proxy_name = input;
        self
    }
    /// <p>The identifier for the DB proxy that is associated with this DB proxy endpoint.</p>
    pub fn get_db_proxy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_proxy_name
    }
    /// <p>The current status of this DB proxy endpoint. A status of <code>available</code> means the endpoint is ready to handle requests. Other values indicate that you must wait for the endpoint to be ready, or take some action to resolve an issue.</p>
    pub fn status(mut self, input: crate::types::DbProxyEndpointStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of this DB proxy endpoint. A status of <code>available</code> means the endpoint is ready to handle requests. Other values indicate that you must wait for the endpoint to be ready, or take some action to resolve an issue.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DbProxyEndpointStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of this DB proxy endpoint. A status of <code>available</code> means the endpoint is ready to handle requests. Other values indicate that you must wait for the endpoint to be ready, or take some action to resolve an issue.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DbProxyEndpointStatus> {
        &self.status
    }
    /// <p>Provides the VPC ID of the DB proxy endpoint.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the VPC ID of the DB proxy endpoint.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>Provides the VPC ID of the DB proxy endpoint.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// Appends an item to `vpc_security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_vpc_security_group_ids`](Self::set_vpc_security_group_ids).
    ///
    /// <p>Provides a list of VPC security groups that the DB proxy endpoint belongs to.</p>
    pub fn vpc_security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.vpc_security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.vpc_security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Provides a list of VPC security groups that the DB proxy endpoint belongs to.</p>
    pub fn set_vpc_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.vpc_security_group_ids = input;
        self
    }
    /// <p>Provides a list of VPC security groups that the DB proxy endpoint belongs to.</p>
    pub fn get_vpc_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.vpc_security_group_ids
    }
    /// Appends an item to `vpc_subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_vpc_subnet_ids`](Self::set_vpc_subnet_ids).
    ///
    /// <p>The EC2 subnet IDs for the DB proxy endpoint.</p>
    pub fn vpc_subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.vpc_subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.vpc_subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The EC2 subnet IDs for the DB proxy endpoint.</p>
    pub fn set_vpc_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.vpc_subnet_ids = input;
        self
    }
    /// <p>The EC2 subnet IDs for the DB proxy endpoint.</p>
    pub fn get_vpc_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.vpc_subnet_ids
    }
    /// <p>The endpoint that you can use to connect to the DB proxy. You include the endpoint value in the connection string for a database client application.</p>
    pub fn endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The endpoint that you can use to connect to the DB proxy. You include the endpoint value in the connection string for a database client application.</p>
    pub fn set_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint = input;
        self
    }
    /// <p>The endpoint that you can use to connect to the DB proxy. You include the endpoint value in the connection string for a database client application.</p>
    pub fn get_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint
    }
    /// <p>The date and time when the DB proxy endpoint was first created.</p>
    pub fn created_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the DB proxy endpoint was first created.</p>
    pub fn set_created_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_date = input;
        self
    }
    /// <p>The date and time when the DB proxy endpoint was first created.</p>
    pub fn get_created_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_date
    }
    /// <p>A value that indicates whether the DB proxy endpoint can be used for read/write or read-only operations.</p>
    pub fn target_role(mut self, input: crate::types::DbProxyEndpointTargetRole) -> Self {
        self.target_role = ::std::option::Option::Some(input);
        self
    }
    /// <p>A value that indicates whether the DB proxy endpoint can be used for read/write or read-only operations.</p>
    pub fn set_target_role(mut self, input: ::std::option::Option<crate::types::DbProxyEndpointTargetRole>) -> Self {
        self.target_role = input;
        self
    }
    /// <p>A value that indicates whether the DB proxy endpoint can be used for read/write or read-only operations.</p>
    pub fn get_target_role(&self) -> &::std::option::Option<crate::types::DbProxyEndpointTargetRole> {
        &self.target_role
    }
    /// <p>Indicates whether this endpoint is the default endpoint for the associated DB proxy. Default DB proxy endpoints always have read/write capability. Other endpoints that you associate with the DB proxy can be either read/write or read-only.</p>
    pub fn is_default(mut self, input: bool) -> Self {
        self.is_default = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether this endpoint is the default endpoint for the associated DB proxy. Default DB proxy endpoints always have read/write capability. Other endpoints that you associate with the DB proxy can be either read/write or read-only.</p>
    pub fn set_is_default(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_default = input;
        self
    }
    /// <p>Indicates whether this endpoint is the default endpoint for the associated DB proxy. Default DB proxy endpoints always have read/write capability. Other endpoints that you associate with the DB proxy can be either read/write or read-only.</p>
    pub fn get_is_default(&self) -> &::std::option::Option<bool> {
        &self.is_default
    }
    /// Consumes the builder and constructs a [`DbProxyEndpoint`](crate::types::DbProxyEndpoint).
    pub fn build(self) -> crate::types::DbProxyEndpoint {
        crate::types::DbProxyEndpoint {
            db_proxy_endpoint_name: self.db_proxy_endpoint_name,
            db_proxy_endpoint_arn: self.db_proxy_endpoint_arn,
            db_proxy_name: self.db_proxy_name,
            status: self.status,
            vpc_id: self.vpc_id,
            vpc_security_group_ids: self.vpc_security_group_ids,
            vpc_subnet_ids: self.vpc_subnet_ids,
            endpoint: self.endpoint,
            created_date: self.created_date,
            target_role: self.target_role,
            is_default: self.is_default,
        }
    }
}
