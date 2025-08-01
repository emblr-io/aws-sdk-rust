// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the RDS options for a Verified Access endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VerifiedAccessEndpointRdsOptions {
    /// <p>The protocol.</p>
    pub protocol: ::std::option::Option<crate::types::VerifiedAccessEndpointProtocol>,
    /// <p>The port.</p>
    pub port: ::std::option::Option<i32>,
    /// <p>The ARN of the RDS instance.</p>
    pub rds_db_instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the DB cluster.</p>
    pub rds_db_cluster_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the RDS proxy.</p>
    pub rds_db_proxy_arn: ::std::option::Option<::std::string::String>,
    /// <p>The RDS endpoint.</p>
    pub rds_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The IDs of the subnets.</p>
    pub subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl VerifiedAccessEndpointRdsOptions {
    /// <p>The protocol.</p>
    pub fn protocol(&self) -> ::std::option::Option<&crate::types::VerifiedAccessEndpointProtocol> {
        self.protocol.as_ref()
    }
    /// <p>The port.</p>
    pub fn port(&self) -> ::std::option::Option<i32> {
        self.port
    }
    /// <p>The ARN of the RDS instance.</p>
    pub fn rds_db_instance_arn(&self) -> ::std::option::Option<&str> {
        self.rds_db_instance_arn.as_deref()
    }
    /// <p>The ARN of the DB cluster.</p>
    pub fn rds_db_cluster_arn(&self) -> ::std::option::Option<&str> {
        self.rds_db_cluster_arn.as_deref()
    }
    /// <p>The ARN of the RDS proxy.</p>
    pub fn rds_db_proxy_arn(&self) -> ::std::option::Option<&str> {
        self.rds_db_proxy_arn.as_deref()
    }
    /// <p>The RDS endpoint.</p>
    pub fn rds_endpoint(&self) -> ::std::option::Option<&str> {
        self.rds_endpoint.as_deref()
    }
    /// <p>The IDs of the subnets.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ids.is_none()`.
    pub fn subnet_ids(&self) -> &[::std::string::String] {
        self.subnet_ids.as_deref().unwrap_or_default()
    }
}
impl VerifiedAccessEndpointRdsOptions {
    /// Creates a new builder-style object to manufacture [`VerifiedAccessEndpointRdsOptions`](crate::types::VerifiedAccessEndpointRdsOptions).
    pub fn builder() -> crate::types::builders::VerifiedAccessEndpointRdsOptionsBuilder {
        crate::types::builders::VerifiedAccessEndpointRdsOptionsBuilder::default()
    }
}

/// A builder for [`VerifiedAccessEndpointRdsOptions`](crate::types::VerifiedAccessEndpointRdsOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VerifiedAccessEndpointRdsOptionsBuilder {
    pub(crate) protocol: ::std::option::Option<crate::types::VerifiedAccessEndpointProtocol>,
    pub(crate) port: ::std::option::Option<i32>,
    pub(crate) rds_db_instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) rds_db_cluster_arn: ::std::option::Option<::std::string::String>,
    pub(crate) rds_db_proxy_arn: ::std::option::Option<::std::string::String>,
    pub(crate) rds_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl VerifiedAccessEndpointRdsOptionsBuilder {
    /// <p>The protocol.</p>
    pub fn protocol(mut self, input: crate::types::VerifiedAccessEndpointProtocol) -> Self {
        self.protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>The protocol.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<crate::types::VerifiedAccessEndpointProtocol>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The protocol.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<crate::types::VerifiedAccessEndpointProtocol> {
        &self.protocol
    }
    /// <p>The port.</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The port.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// <p>The ARN of the RDS instance.</p>
    pub fn rds_db_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rds_db_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the RDS instance.</p>
    pub fn set_rds_db_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rds_db_instance_arn = input;
        self
    }
    /// <p>The ARN of the RDS instance.</p>
    pub fn get_rds_db_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.rds_db_instance_arn
    }
    /// <p>The ARN of the DB cluster.</p>
    pub fn rds_db_cluster_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rds_db_cluster_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the DB cluster.</p>
    pub fn set_rds_db_cluster_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rds_db_cluster_arn = input;
        self
    }
    /// <p>The ARN of the DB cluster.</p>
    pub fn get_rds_db_cluster_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.rds_db_cluster_arn
    }
    /// <p>The ARN of the RDS proxy.</p>
    pub fn rds_db_proxy_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rds_db_proxy_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the RDS proxy.</p>
    pub fn set_rds_db_proxy_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rds_db_proxy_arn = input;
        self
    }
    /// <p>The ARN of the RDS proxy.</p>
    pub fn get_rds_db_proxy_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.rds_db_proxy_arn
    }
    /// <p>The RDS endpoint.</p>
    pub fn rds_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rds_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The RDS endpoint.</p>
    pub fn set_rds_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rds_endpoint = input;
        self
    }
    /// <p>The RDS endpoint.</p>
    pub fn get_rds_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.rds_endpoint
    }
    /// Appends an item to `subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_subnet_ids`](Self::set_subnet_ids).
    ///
    /// <p>The IDs of the subnets.</p>
    pub fn subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the subnets.</p>
    pub fn set_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnet_ids = input;
        self
    }
    /// <p>The IDs of the subnets.</p>
    pub fn get_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnet_ids
    }
    /// Consumes the builder and constructs a [`VerifiedAccessEndpointRdsOptions`](crate::types::VerifiedAccessEndpointRdsOptions).
    pub fn build(self) -> crate::types::VerifiedAccessEndpointRdsOptions {
        crate::types::VerifiedAccessEndpointRdsOptions {
            protocol: self.protocol,
            port: self.port,
            rds_db_instance_arn: self.rds_db_instance_arn,
            rds_db_cluster_arn: self.rds_db_cluster_arn,
            rds_db_proxy_arn: self.rds_db_proxy_arn,
            rds_endpoint: self.rds_endpoint,
            subnet_ids: self.subnet_ids,
        }
    }
}
