// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the subnet group for the database instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsRdsDbSubnetGroup {
    /// <p>The name of the subnet group.</p>
    pub db_subnet_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the subnet group.</p>
    pub db_subnet_group_description: ::std::option::Option<::std::string::String>,
    /// <p>The VPC ID of the subnet group.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the subnet group.</p>
    pub subnet_group_status: ::std::option::Option<::std::string::String>,
    /// <p>A list of subnets in the subnet group.</p>
    pub subnets: ::std::option::Option<::std::vec::Vec<crate::types::AwsRdsDbSubnetGroupSubnet>>,
    /// <p>The ARN of the subnet group.</p>
    pub db_subnet_group_arn: ::std::option::Option<::std::string::String>,
}
impl AwsRdsDbSubnetGroup {
    /// <p>The name of the subnet group.</p>
    pub fn db_subnet_group_name(&self) -> ::std::option::Option<&str> {
        self.db_subnet_group_name.as_deref()
    }
    /// <p>The description of the subnet group.</p>
    pub fn db_subnet_group_description(&self) -> ::std::option::Option<&str> {
        self.db_subnet_group_description.as_deref()
    }
    /// <p>The VPC ID of the subnet group.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>The status of the subnet group.</p>
    pub fn subnet_group_status(&self) -> ::std::option::Option<&str> {
        self.subnet_group_status.as_deref()
    }
    /// <p>A list of subnets in the subnet group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnets.is_none()`.
    pub fn subnets(&self) -> &[crate::types::AwsRdsDbSubnetGroupSubnet] {
        self.subnets.as_deref().unwrap_or_default()
    }
    /// <p>The ARN of the subnet group.</p>
    pub fn db_subnet_group_arn(&self) -> ::std::option::Option<&str> {
        self.db_subnet_group_arn.as_deref()
    }
}
impl AwsRdsDbSubnetGroup {
    /// Creates a new builder-style object to manufacture [`AwsRdsDbSubnetGroup`](crate::types::AwsRdsDbSubnetGroup).
    pub fn builder() -> crate::types::builders::AwsRdsDbSubnetGroupBuilder {
        crate::types::builders::AwsRdsDbSubnetGroupBuilder::default()
    }
}

/// A builder for [`AwsRdsDbSubnetGroup`](crate::types::AwsRdsDbSubnetGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsRdsDbSubnetGroupBuilder {
    pub(crate) db_subnet_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) db_subnet_group_description: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_group_status: ::std::option::Option<::std::string::String>,
    pub(crate) subnets: ::std::option::Option<::std::vec::Vec<crate::types::AwsRdsDbSubnetGroupSubnet>>,
    pub(crate) db_subnet_group_arn: ::std::option::Option<::std::string::String>,
}
impl AwsRdsDbSubnetGroupBuilder {
    /// <p>The name of the subnet group.</p>
    pub fn db_subnet_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_subnet_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the subnet group.</p>
    pub fn set_db_subnet_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_subnet_group_name = input;
        self
    }
    /// <p>The name of the subnet group.</p>
    pub fn get_db_subnet_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_subnet_group_name
    }
    /// <p>The description of the subnet group.</p>
    pub fn db_subnet_group_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_subnet_group_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the subnet group.</p>
    pub fn set_db_subnet_group_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_subnet_group_description = input;
        self
    }
    /// <p>The description of the subnet group.</p>
    pub fn get_db_subnet_group_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_subnet_group_description
    }
    /// <p>The VPC ID of the subnet group.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The VPC ID of the subnet group.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The VPC ID of the subnet group.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// <p>The status of the subnet group.</p>
    pub fn subnet_group_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_group_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the subnet group.</p>
    pub fn set_subnet_group_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_group_status = input;
        self
    }
    /// <p>The status of the subnet group.</p>
    pub fn get_subnet_group_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_group_status
    }
    /// Appends an item to `subnets`.
    ///
    /// To override the contents of this collection use [`set_subnets`](Self::set_subnets).
    ///
    /// <p>A list of subnets in the subnet group.</p>
    pub fn subnets(mut self, input: crate::types::AwsRdsDbSubnetGroupSubnet) -> Self {
        let mut v = self.subnets.unwrap_or_default();
        v.push(input);
        self.subnets = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of subnets in the subnet group.</p>
    pub fn set_subnets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AwsRdsDbSubnetGroupSubnet>>) -> Self {
        self.subnets = input;
        self
    }
    /// <p>A list of subnets in the subnet group.</p>
    pub fn get_subnets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsRdsDbSubnetGroupSubnet>> {
        &self.subnets
    }
    /// <p>The ARN of the subnet group.</p>
    pub fn db_subnet_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_subnet_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the subnet group.</p>
    pub fn set_db_subnet_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_subnet_group_arn = input;
        self
    }
    /// <p>The ARN of the subnet group.</p>
    pub fn get_db_subnet_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_subnet_group_arn
    }
    /// Consumes the builder and constructs a [`AwsRdsDbSubnetGroup`](crate::types::AwsRdsDbSubnetGroup).
    pub fn build(self) -> crate::types::AwsRdsDbSubnetGroup {
        crate::types::AwsRdsDbSubnetGroup {
            db_subnet_group_name: self.db_subnet_group_name,
            db_subnet_group_description: self.db_subnet_group_description,
            vpc_id: self.vpc_id,
            subnet_group_status: self.subnet_group_status,
            subnets: self.subnets,
            db_subnet_group_arn: self.db_subnet_group_arn,
        }
    }
}
