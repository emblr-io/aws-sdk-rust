// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateVpcConnectionInput {
    /// <p>The Amazon Web Services account ID of the account that contains the VPC connection that you want to update.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the VPC connection that you're updating. This ID is a unique identifier for each Amazon Web Services Region in an Amazon Web Services account.</p>
    pub vpc_connection_id: ::std::option::Option<::std::string::String>,
    /// <p>The display name for the VPC connection.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A list of subnet IDs for the VPC connection.</p>
    pub subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of security group IDs for the VPC connection.</p>
    pub security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of IP addresses of DNS resolver endpoints for the VPC connection.</p>
    pub dns_resolvers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An IAM role associated with the VPC connection.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateVpcConnectionInput {
    /// <p>The Amazon Web Services account ID of the account that contains the VPC connection that you want to update.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID of the VPC connection that you're updating. This ID is a unique identifier for each Amazon Web Services Region in an Amazon Web Services account.</p>
    pub fn vpc_connection_id(&self) -> ::std::option::Option<&str> {
        self.vpc_connection_id.as_deref()
    }
    /// <p>The display name for the VPC connection.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A list of subnet IDs for the VPC connection.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ids.is_none()`.
    pub fn subnet_ids(&self) -> &[::std::string::String] {
        self.subnet_ids.as_deref().unwrap_or_default()
    }
    /// <p>A list of security group IDs for the VPC connection.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_ids.is_none()`.
    pub fn security_group_ids(&self) -> &[::std::string::String] {
        self.security_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>A list of IP addresses of DNS resolver endpoints for the VPC connection.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dns_resolvers.is_none()`.
    pub fn dns_resolvers(&self) -> &[::std::string::String] {
        self.dns_resolvers.as_deref().unwrap_or_default()
    }
    /// <p>An IAM role associated with the VPC connection.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
}
impl UpdateVpcConnectionInput {
    /// Creates a new builder-style object to manufacture [`UpdateVpcConnectionInput`](crate::operation::update_vpc_connection::UpdateVpcConnectionInput).
    pub fn builder() -> crate::operation::update_vpc_connection::builders::UpdateVpcConnectionInputBuilder {
        crate::operation::update_vpc_connection::builders::UpdateVpcConnectionInputBuilder::default()
    }
}

/// A builder for [`UpdateVpcConnectionInput`](crate::operation::update_vpc_connection::UpdateVpcConnectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateVpcConnectionInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_connection_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) dns_resolvers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateVpcConnectionInputBuilder {
    /// <p>The Amazon Web Services account ID of the account that contains the VPC connection that you want to update.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the account that contains the VPC connection that you want to update.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the account that contains the VPC connection that you want to update.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID of the VPC connection that you're updating. This ID is a unique identifier for each Amazon Web Services Region in an Amazon Web Services account.</p>
    /// This field is required.
    pub fn vpc_connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the VPC connection that you're updating. This ID is a unique identifier for each Amazon Web Services Region in an Amazon Web Services account.</p>
    pub fn set_vpc_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_connection_id = input;
        self
    }
    /// <p>The ID of the VPC connection that you're updating. This ID is a unique identifier for each Amazon Web Services Region in an Amazon Web Services account.</p>
    pub fn get_vpc_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_connection_id
    }
    /// <p>The display name for the VPC connection.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name for the VPC connection.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The display name for the VPC connection.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_subnet_ids`](Self::set_subnet_ids).
    ///
    /// <p>A list of subnet IDs for the VPC connection.</p>
    pub fn subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of subnet IDs for the VPC connection.</p>
    pub fn set_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnet_ids = input;
        self
    }
    /// <p>A list of subnet IDs for the VPC connection.</p>
    pub fn get_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnet_ids
    }
    /// Appends an item to `security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_security_group_ids`](Self::set_security_group_ids).
    ///
    /// <p>A list of security group IDs for the VPC connection.</p>
    pub fn security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of security group IDs for the VPC connection.</p>
    pub fn set_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_group_ids = input;
        self
    }
    /// <p>A list of security group IDs for the VPC connection.</p>
    pub fn get_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_group_ids
    }
    /// Appends an item to `dns_resolvers`.
    ///
    /// To override the contents of this collection use [`set_dns_resolvers`](Self::set_dns_resolvers).
    ///
    /// <p>A list of IP addresses of DNS resolver endpoints for the VPC connection.</p>
    pub fn dns_resolvers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.dns_resolvers.unwrap_or_default();
        v.push(input.into());
        self.dns_resolvers = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of IP addresses of DNS resolver endpoints for the VPC connection.</p>
    pub fn set_dns_resolvers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.dns_resolvers = input;
        self
    }
    /// <p>A list of IP addresses of DNS resolver endpoints for the VPC connection.</p>
    pub fn get_dns_resolvers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.dns_resolvers
    }
    /// <p>An IAM role associated with the VPC connection.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An IAM role associated with the VPC connection.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>An IAM role associated with the VPC connection.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`UpdateVpcConnectionInput`](crate::operation::update_vpc_connection::UpdateVpcConnectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_vpc_connection::UpdateVpcConnectionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_vpc_connection::UpdateVpcConnectionInput {
            aws_account_id: self.aws_account_id,
            vpc_connection_id: self.vpc_connection_id,
            name: self.name,
            subnet_ids: self.subnet_ids,
            security_group_ids: self.security_group_ids,
            dns_resolvers: self.dns_resolvers,
            role_arn: self.role_arn,
        })
    }
}
