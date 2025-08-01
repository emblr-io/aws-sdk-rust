// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEndpointAccessInput {
    /// <p>The name of the VPC endpoint. An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    pub endpoint_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifers of subnets from which Amazon Redshift Serverless chooses one to deploy a VPC endpoint.</p>
    pub subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the workgroup to associate with the VPC endpoint.</p>
    pub workgroup_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifiers of the security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    pub vpc_security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The owner Amazon Web Services account for the Amazon Redshift Serverless workgroup.</p>
    pub owner_account: ::std::option::Option<::std::string::String>,
}
impl CreateEndpointAccessInput {
    /// <p>The name of the VPC endpoint. An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    pub fn endpoint_name(&self) -> ::std::option::Option<&str> {
        self.endpoint_name.as_deref()
    }
    /// <p>The unique identifers of subnets from which Amazon Redshift Serverless chooses one to deploy a VPC endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ids.is_none()`.
    pub fn subnet_ids(&self) -> &[::std::string::String] {
        self.subnet_ids.as_deref().unwrap_or_default()
    }
    /// <p>The name of the workgroup to associate with the VPC endpoint.</p>
    pub fn workgroup_name(&self) -> ::std::option::Option<&str> {
        self.workgroup_name.as_deref()
    }
    /// <p>The unique identifiers of the security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_security_group_ids.is_none()`.
    pub fn vpc_security_group_ids(&self) -> &[::std::string::String] {
        self.vpc_security_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>The owner Amazon Web Services account for the Amazon Redshift Serverless workgroup.</p>
    pub fn owner_account(&self) -> ::std::option::Option<&str> {
        self.owner_account.as_deref()
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
    pub(crate) endpoint_name: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) workgroup_name: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) owner_account: ::std::option::Option<::std::string::String>,
}
impl CreateEndpointAccessInputBuilder {
    /// <p>The name of the VPC endpoint. An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    /// This field is required.
    pub fn endpoint_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the VPC endpoint. An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    pub fn set_endpoint_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_name = input;
        self
    }
    /// <p>The name of the VPC endpoint. An endpoint name must contain 1-30 characters. Valid characters are A-Z, a-z, 0-9, and hyphen(-). The first character must be a letter. The name can't contain two consecutive hyphens or end with a hyphen.</p>
    pub fn get_endpoint_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_name
    }
    /// Appends an item to `subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_subnet_ids`](Self::set_subnet_ids).
    ///
    /// <p>The unique identifers of subnets from which Amazon Redshift Serverless chooses one to deploy a VPC endpoint.</p>
    pub fn subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The unique identifers of subnets from which Amazon Redshift Serverless chooses one to deploy a VPC endpoint.</p>
    pub fn set_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnet_ids = input;
        self
    }
    /// <p>The unique identifers of subnets from which Amazon Redshift Serverless chooses one to deploy a VPC endpoint.</p>
    pub fn get_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnet_ids
    }
    /// <p>The name of the workgroup to associate with the VPC endpoint.</p>
    /// This field is required.
    pub fn workgroup_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workgroup_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the workgroup to associate with the VPC endpoint.</p>
    pub fn set_workgroup_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workgroup_name = input;
        self
    }
    /// <p>The name of the workgroup to associate with the VPC endpoint.</p>
    pub fn get_workgroup_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.workgroup_name
    }
    /// Appends an item to `vpc_security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_vpc_security_group_ids`](Self::set_vpc_security_group_ids).
    ///
    /// <p>The unique identifiers of the security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    pub fn vpc_security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.vpc_security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.vpc_security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The unique identifiers of the security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    pub fn set_vpc_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.vpc_security_group_ids = input;
        self
    }
    /// <p>The unique identifiers of the security group that defines the ports, protocols, and sources for inbound traffic that you are authorizing into your endpoint.</p>
    pub fn get_vpc_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.vpc_security_group_ids
    }
    /// <p>The owner Amazon Web Services account for the Amazon Redshift Serverless workgroup.</p>
    pub fn owner_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner Amazon Web Services account for the Amazon Redshift Serverless workgroup.</p>
    pub fn set_owner_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_account = input;
        self
    }
    /// <p>The owner Amazon Web Services account for the Amazon Redshift Serverless workgroup.</p>
    pub fn get_owner_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_account
    }
    /// Consumes the builder and constructs a [`CreateEndpointAccessInput`](crate::operation::create_endpoint_access::CreateEndpointAccessInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_endpoint_access::CreateEndpointAccessInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_endpoint_access::CreateEndpointAccessInput {
            endpoint_name: self.endpoint_name,
            subnet_ids: self.subnet_ids,
            workgroup_name: self.workgroup_name,
            vpc_security_group_ids: self.vpc_security_group_ids,
            owner_account: self.owner_account,
        })
    }
}
