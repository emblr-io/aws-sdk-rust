// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the details of an Amazon RDS DB subnet group.</p>
/// <p>This data type is used as a response element in the <code>DescribeDBSubnetGroups</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DbSubnetGroup {
    /// <p>The name of the DB subnet group.</p>
    pub db_subnet_group_name: ::std::option::Option<::std::string::String>,
    /// <p>Provides the description of the DB subnet group.</p>
    pub db_subnet_group_description: ::std::option::Option<::std::string::String>,
    /// <p>Provides the VpcId of the DB subnet group.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>Provides the status of the DB subnet group.</p>
    pub subnet_group_status: ::std::option::Option<::std::string::String>,
    /// <p>Contains a list of <code>Subnet</code> elements. The list of subnets shown here might not reflect the current state of your VPC. For the most up-to-date information, we recommend checking your VPC configuration directly.</p>
    pub subnets: ::std::option::Option<::std::vec::Vec<crate::types::Subnet>>,
    /// <p>The Amazon Resource Name (ARN) for the DB subnet group.</p>
    pub db_subnet_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The network type of the DB subnet group.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>IPV4</code></p></li>
    /// <li>
    /// <p><code>DUAL</code></p></li>
    /// </ul>
    /// <p>A <code>DBSubnetGroup</code> can support only the IPv4 protocol or the IPv4 and the IPv6 protocols (<code>DUAL</code>).</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"> Working with a DB instance in a VPC</a> in the <i>Amazon RDS User Guide.</i></p>
    pub supported_network_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DbSubnetGroup {
    /// <p>The name of the DB subnet group.</p>
    pub fn db_subnet_group_name(&self) -> ::std::option::Option<&str> {
        self.db_subnet_group_name.as_deref()
    }
    /// <p>Provides the description of the DB subnet group.</p>
    pub fn db_subnet_group_description(&self) -> ::std::option::Option<&str> {
        self.db_subnet_group_description.as_deref()
    }
    /// <p>Provides the VpcId of the DB subnet group.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>Provides the status of the DB subnet group.</p>
    pub fn subnet_group_status(&self) -> ::std::option::Option<&str> {
        self.subnet_group_status.as_deref()
    }
    /// <p>Contains a list of <code>Subnet</code> elements. The list of subnets shown here might not reflect the current state of your VPC. For the most up-to-date information, we recommend checking your VPC configuration directly.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnets.is_none()`.
    pub fn subnets(&self) -> &[crate::types::Subnet] {
        self.subnets.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) for the DB subnet group.</p>
    pub fn db_subnet_group_arn(&self) -> ::std::option::Option<&str> {
        self.db_subnet_group_arn.as_deref()
    }
    /// <p>The network type of the DB subnet group.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>IPV4</code></p></li>
    /// <li>
    /// <p><code>DUAL</code></p></li>
    /// </ul>
    /// <p>A <code>DBSubnetGroup</code> can support only the IPv4 protocol or the IPv4 and the IPv6 protocols (<code>DUAL</code>).</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"> Working with a DB instance in a VPC</a> in the <i>Amazon RDS User Guide.</i></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_network_types.is_none()`.
    pub fn supported_network_types(&self) -> &[::std::string::String] {
        self.supported_network_types.as_deref().unwrap_or_default()
    }
}
impl DbSubnetGroup {
    /// Creates a new builder-style object to manufacture [`DbSubnetGroup`](crate::types::DbSubnetGroup).
    pub fn builder() -> crate::types::builders::DbSubnetGroupBuilder {
        crate::types::builders::DbSubnetGroupBuilder::default()
    }
}

/// A builder for [`DbSubnetGroup`](crate::types::DbSubnetGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DbSubnetGroupBuilder {
    pub(crate) db_subnet_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) db_subnet_group_description: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_group_status: ::std::option::Option<::std::string::String>,
    pub(crate) subnets: ::std::option::Option<::std::vec::Vec<crate::types::Subnet>>,
    pub(crate) db_subnet_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) supported_network_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DbSubnetGroupBuilder {
    /// <p>The name of the DB subnet group.</p>
    pub fn db_subnet_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_subnet_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the DB subnet group.</p>
    pub fn set_db_subnet_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_subnet_group_name = input;
        self
    }
    /// <p>The name of the DB subnet group.</p>
    pub fn get_db_subnet_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_subnet_group_name
    }
    /// <p>Provides the description of the DB subnet group.</p>
    pub fn db_subnet_group_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_subnet_group_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the description of the DB subnet group.</p>
    pub fn set_db_subnet_group_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_subnet_group_description = input;
        self
    }
    /// <p>Provides the description of the DB subnet group.</p>
    pub fn get_db_subnet_group_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_subnet_group_description
    }
    /// <p>Provides the VpcId of the DB subnet group.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the VpcId of the DB subnet group.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>Provides the VpcId of the DB subnet group.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// <p>Provides the status of the DB subnet group.</p>
    pub fn subnet_group_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_group_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the status of the DB subnet group.</p>
    pub fn set_subnet_group_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_group_status = input;
        self
    }
    /// <p>Provides the status of the DB subnet group.</p>
    pub fn get_subnet_group_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_group_status
    }
    /// Appends an item to `subnets`.
    ///
    /// To override the contents of this collection use [`set_subnets`](Self::set_subnets).
    ///
    /// <p>Contains a list of <code>Subnet</code> elements. The list of subnets shown here might not reflect the current state of your VPC. For the most up-to-date information, we recommend checking your VPC configuration directly.</p>
    pub fn subnets(mut self, input: crate::types::Subnet) -> Self {
        let mut v = self.subnets.unwrap_or_default();
        v.push(input);
        self.subnets = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains a list of <code>Subnet</code> elements. The list of subnets shown here might not reflect the current state of your VPC. For the most up-to-date information, we recommend checking your VPC configuration directly.</p>
    pub fn set_subnets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Subnet>>) -> Self {
        self.subnets = input;
        self
    }
    /// <p>Contains a list of <code>Subnet</code> elements. The list of subnets shown here might not reflect the current state of your VPC. For the most up-to-date information, we recommend checking your VPC configuration directly.</p>
    pub fn get_subnets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Subnet>> {
        &self.subnets
    }
    /// <p>The Amazon Resource Name (ARN) for the DB subnet group.</p>
    pub fn db_subnet_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_subnet_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the DB subnet group.</p>
    pub fn set_db_subnet_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_subnet_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the DB subnet group.</p>
    pub fn get_db_subnet_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_subnet_group_arn
    }
    /// Appends an item to `supported_network_types`.
    ///
    /// To override the contents of this collection use [`set_supported_network_types`](Self::set_supported_network_types).
    ///
    /// <p>The network type of the DB subnet group.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>IPV4</code></p></li>
    /// <li>
    /// <p><code>DUAL</code></p></li>
    /// </ul>
    /// <p>A <code>DBSubnetGroup</code> can support only the IPv4 protocol or the IPv4 and the IPv6 protocols (<code>DUAL</code>).</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"> Working with a DB instance in a VPC</a> in the <i>Amazon RDS User Guide.</i></p>
    pub fn supported_network_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.supported_network_types.unwrap_or_default();
        v.push(input.into());
        self.supported_network_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The network type of the DB subnet group.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>IPV4</code></p></li>
    /// <li>
    /// <p><code>DUAL</code></p></li>
    /// </ul>
    /// <p>A <code>DBSubnetGroup</code> can support only the IPv4 protocol or the IPv4 and the IPv6 protocols (<code>DUAL</code>).</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"> Working with a DB instance in a VPC</a> in the <i>Amazon RDS User Guide.</i></p>
    pub fn set_supported_network_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.supported_network_types = input;
        self
    }
    /// <p>The network type of the DB subnet group.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p><code>IPV4</code></p></li>
    /// <li>
    /// <p><code>DUAL</code></p></li>
    /// </ul>
    /// <p>A <code>DBSubnetGroup</code> can support only the IPv4 protocol or the IPv4 and the IPv6 protocols (<code>DUAL</code>).</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"> Working with a DB instance in a VPC</a> in the <i>Amazon RDS User Guide.</i></p>
    pub fn get_supported_network_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.supported_network_types
    }
    /// Consumes the builder and constructs a [`DbSubnetGroup`](crate::types::DbSubnetGroup).
    pub fn build(self) -> crate::types::DbSubnetGroup {
        crate::types::DbSubnetGroup {
            db_subnet_group_name: self.db_subnet_group_name,
            db_subnet_group_description: self.db_subnet_group_description,
            vpc_id: self.vpc_id,
            subnet_group_status: self.subnet_group_status,
            subnets: self.subnets,
            db_subnet_group_arn: self.db_subnet_group_arn,
            supported_network_types: self.supported_network_types,
        }
    }
}
