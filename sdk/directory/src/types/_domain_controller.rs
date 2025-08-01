// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the domain controllers for a specified directory.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DomainController {
    /// <p>Identifier of the directory where the domain controller resides.</p>
    pub directory_id: ::std::option::Option<::std::string::String>,
    /// <p>Identifies a specific domain controller in the directory.</p>
    pub domain_controller_id: ::std::option::Option<::std::string::String>,
    /// <p>The IP address of the domain controller.</p>
    pub dns_ip_addr: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the VPC that contains the domain controller.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>Identifier of the subnet in the VPC that contains the domain controller.</p>
    pub subnet_id: ::std::option::Option<::std::string::String>,
    /// <p>The Availability Zone where the domain controller is located.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>The status of the domain controller.</p>
    pub status: ::std::option::Option<crate::types::DomainControllerStatus>,
    /// <p>A description of the domain controller state.</p>
    pub status_reason: ::std::option::Option<::std::string::String>,
    /// <p>Specifies when the domain controller was created.</p>
    pub launch_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the status was last updated.</p>
    pub status_last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl DomainController {
    /// <p>Identifier of the directory where the domain controller resides.</p>
    pub fn directory_id(&self) -> ::std::option::Option<&str> {
        self.directory_id.as_deref()
    }
    /// <p>Identifies a specific domain controller in the directory.</p>
    pub fn domain_controller_id(&self) -> ::std::option::Option<&str> {
        self.domain_controller_id.as_deref()
    }
    /// <p>The IP address of the domain controller.</p>
    pub fn dns_ip_addr(&self) -> ::std::option::Option<&str> {
        self.dns_ip_addr.as_deref()
    }
    /// <p>The identifier of the VPC that contains the domain controller.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>Identifier of the subnet in the VPC that contains the domain controller.</p>
    pub fn subnet_id(&self) -> ::std::option::Option<&str> {
        self.subnet_id.as_deref()
    }
    /// <p>The Availability Zone where the domain controller is located.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>The status of the domain controller.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DomainControllerStatus> {
        self.status.as_ref()
    }
    /// <p>A description of the domain controller state.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&str> {
        self.status_reason.as_deref()
    }
    /// <p>Specifies when the domain controller was created.</p>
    pub fn launch_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.launch_time.as_ref()
    }
    /// <p>The date and time that the status was last updated.</p>
    pub fn status_last_updated_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.status_last_updated_date_time.as_ref()
    }
}
impl DomainController {
    /// Creates a new builder-style object to manufacture [`DomainController`](crate::types::DomainController).
    pub fn builder() -> crate::types::builders::DomainControllerBuilder {
        crate::types::builders::DomainControllerBuilder::default()
    }
}

/// A builder for [`DomainController`](crate::types::DomainController).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DomainControllerBuilder {
    pub(crate) directory_id: ::std::option::Option<::std::string::String>,
    pub(crate) domain_controller_id: ::std::option::Option<::std::string::String>,
    pub(crate) dns_ip_addr: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_id: ::std::option::Option<::std::string::String>,
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::DomainControllerStatus>,
    pub(crate) status_reason: ::std::option::Option<::std::string::String>,
    pub(crate) launch_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status_last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl DomainControllerBuilder {
    /// <p>Identifier of the directory where the domain controller resides.</p>
    pub fn directory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier of the directory where the domain controller resides.</p>
    pub fn set_directory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_id = input;
        self
    }
    /// <p>Identifier of the directory where the domain controller resides.</p>
    pub fn get_directory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_id
    }
    /// <p>Identifies a specific domain controller in the directory.</p>
    pub fn domain_controller_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_controller_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifies a specific domain controller in the directory.</p>
    pub fn set_domain_controller_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_controller_id = input;
        self
    }
    /// <p>Identifies a specific domain controller in the directory.</p>
    pub fn get_domain_controller_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_controller_id
    }
    /// <p>The IP address of the domain controller.</p>
    pub fn dns_ip_addr(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dns_ip_addr = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IP address of the domain controller.</p>
    pub fn set_dns_ip_addr(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dns_ip_addr = input;
        self
    }
    /// <p>The IP address of the domain controller.</p>
    pub fn get_dns_ip_addr(&self) -> &::std::option::Option<::std::string::String> {
        &self.dns_ip_addr
    }
    /// <p>The identifier of the VPC that contains the domain controller.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the VPC that contains the domain controller.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The identifier of the VPC that contains the domain controller.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// <p>Identifier of the subnet in the VPC that contains the domain controller.</p>
    pub fn subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier of the subnet in the VPC that contains the domain controller.</p>
    pub fn set_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_id = input;
        self
    }
    /// <p>Identifier of the subnet in the VPC that contains the domain controller.</p>
    pub fn get_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_id
    }
    /// <p>The Availability Zone where the domain controller is located.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Availability Zone where the domain controller is located.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The Availability Zone where the domain controller is located.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// <p>The status of the domain controller.</p>
    pub fn status(mut self, input: crate::types::DomainControllerStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the domain controller.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DomainControllerStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the domain controller.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DomainControllerStatus> {
        &self.status
    }
    /// <p>A description of the domain controller state.</p>
    pub fn status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the domain controller state.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>A description of the domain controller state.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_reason
    }
    /// <p>Specifies when the domain controller was created.</p>
    pub fn launch_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.launch_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies when the domain controller was created.</p>
    pub fn set_launch_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.launch_time = input;
        self
    }
    /// <p>Specifies when the domain controller was created.</p>
    pub fn get_launch_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.launch_time
    }
    /// <p>The date and time that the status was last updated.</p>
    pub fn status_last_updated_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.status_last_updated_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the status was last updated.</p>
    pub fn set_status_last_updated_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.status_last_updated_date_time = input;
        self
    }
    /// <p>The date and time that the status was last updated.</p>
    pub fn get_status_last_updated_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.status_last_updated_date_time
    }
    /// Consumes the builder and constructs a [`DomainController`](crate::types::DomainController).
    pub fn build(self) -> crate::types::DomainController {
        crate::types::DomainController {
            directory_id: self.directory_id,
            domain_controller_id: self.domain_controller_id,
            dns_ip_addr: self.dns_ip_addr,
            vpc_id: self.vpc_id,
            subnet_id: self.subnet_id,
            availability_zone: self.availability_zone,
            status: self.status,
            status_reason: self.status_reason,
            launch_time: self.launch_time,
            status_last_updated_date_time: self.status_last_updated_date_time,
        }
    }
}
