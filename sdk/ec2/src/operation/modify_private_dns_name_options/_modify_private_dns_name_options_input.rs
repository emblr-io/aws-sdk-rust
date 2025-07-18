// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyPrivateDnsNameOptionsInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The ID of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of hostname for EC2 instances. For IPv4 only subnets, an instance DNS name must be based on the instance IPv4 address. For IPv6 only subnets, an instance DNS name must be based on the instance ID. For dual-stack subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID.</p>
    pub private_dns_hostname_type: ::std::option::Option<crate::types::HostnameType>,
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS A records.</p>
    pub enable_resource_name_dns_a_record: ::std::option::Option<bool>,
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records.</p>
    pub enable_resource_name_dns_aaaa_record: ::std::option::Option<bool>,
}
impl ModifyPrivateDnsNameOptionsInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The ID of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The type of hostname for EC2 instances. For IPv4 only subnets, an instance DNS name must be based on the instance IPv4 address. For IPv6 only subnets, an instance DNS name must be based on the instance ID. For dual-stack subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID.</p>
    pub fn private_dns_hostname_type(&self) -> ::std::option::Option<&crate::types::HostnameType> {
        self.private_dns_hostname_type.as_ref()
    }
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS A records.</p>
    pub fn enable_resource_name_dns_a_record(&self) -> ::std::option::Option<bool> {
        self.enable_resource_name_dns_a_record
    }
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records.</p>
    pub fn enable_resource_name_dns_aaaa_record(&self) -> ::std::option::Option<bool> {
        self.enable_resource_name_dns_aaaa_record
    }
}
impl ModifyPrivateDnsNameOptionsInput {
    /// Creates a new builder-style object to manufacture [`ModifyPrivateDnsNameOptionsInput`](crate::operation::modify_private_dns_name_options::ModifyPrivateDnsNameOptionsInput).
    pub fn builder() -> crate::operation::modify_private_dns_name_options::builders::ModifyPrivateDnsNameOptionsInputBuilder {
        crate::operation::modify_private_dns_name_options::builders::ModifyPrivateDnsNameOptionsInputBuilder::default()
    }
}

/// A builder for [`ModifyPrivateDnsNameOptionsInput`](crate::operation::modify_private_dns_name_options::ModifyPrivateDnsNameOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyPrivateDnsNameOptionsInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) private_dns_hostname_type: ::std::option::Option<crate::types::HostnameType>,
    pub(crate) enable_resource_name_dns_a_record: ::std::option::Option<bool>,
    pub(crate) enable_resource_name_dns_aaaa_record: ::std::option::Option<bool>,
}
impl ModifyPrivateDnsNameOptionsInputBuilder {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>The ID of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The ID of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The type of hostname for EC2 instances. For IPv4 only subnets, an instance DNS name must be based on the instance IPv4 address. For IPv6 only subnets, an instance DNS name must be based on the instance ID. For dual-stack subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID.</p>
    pub fn private_dns_hostname_type(mut self, input: crate::types::HostnameType) -> Self {
        self.private_dns_hostname_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of hostname for EC2 instances. For IPv4 only subnets, an instance DNS name must be based on the instance IPv4 address. For IPv6 only subnets, an instance DNS name must be based on the instance ID. For dual-stack subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID.</p>
    pub fn set_private_dns_hostname_type(mut self, input: ::std::option::Option<crate::types::HostnameType>) -> Self {
        self.private_dns_hostname_type = input;
        self
    }
    /// <p>The type of hostname for EC2 instances. For IPv4 only subnets, an instance DNS name must be based on the instance IPv4 address. For IPv6 only subnets, an instance DNS name must be based on the instance ID. For dual-stack subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID.</p>
    pub fn get_private_dns_hostname_type(&self) -> &::std::option::Option<crate::types::HostnameType> {
        &self.private_dns_hostname_type
    }
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS A records.</p>
    pub fn enable_resource_name_dns_a_record(mut self, input: bool) -> Self {
        self.enable_resource_name_dns_a_record = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS A records.</p>
    pub fn set_enable_resource_name_dns_a_record(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_resource_name_dns_a_record = input;
        self
    }
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS A records.</p>
    pub fn get_enable_resource_name_dns_a_record(&self) -> &::std::option::Option<bool> {
        &self.enable_resource_name_dns_a_record
    }
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records.</p>
    pub fn enable_resource_name_dns_aaaa_record(mut self, input: bool) -> Self {
        self.enable_resource_name_dns_aaaa_record = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records.</p>
    pub fn set_enable_resource_name_dns_aaaa_record(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_resource_name_dns_aaaa_record = input;
        self
    }
    /// <p>Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records.</p>
    pub fn get_enable_resource_name_dns_aaaa_record(&self) -> &::std::option::Option<bool> {
        &self.enable_resource_name_dns_aaaa_record
    }
    /// Consumes the builder and constructs a [`ModifyPrivateDnsNameOptionsInput`](crate::operation::modify_private_dns_name_options::ModifyPrivateDnsNameOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_private_dns_name_options::ModifyPrivateDnsNameOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_private_dns_name_options::ModifyPrivateDnsNameOptionsInput {
            dry_run: self.dry_run,
            instance_id: self.instance_id,
            private_dns_hostname_type: self.private_dns_hostname_type,
            enable_resource_name_dns_a_record: self.enable_resource_name_dns_a_record,
            enable_resource_name_dns_aaaa_record: self.enable_resource_name_dns_aaaa_record,
        })
    }
}
