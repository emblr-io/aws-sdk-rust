// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An association between the network ACL and a subnet.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEc2NetworkAclAssociation {
    /// <p>The identifier of the association between the network ACL and the subnet.</p>
    pub network_acl_association_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the network ACL.</p>
    pub network_acl_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the subnet that is associated with the network ACL.</p>
    pub subnet_id: ::std::option::Option<::std::string::String>,
}
impl AwsEc2NetworkAclAssociation {
    /// <p>The identifier of the association between the network ACL and the subnet.</p>
    pub fn network_acl_association_id(&self) -> ::std::option::Option<&str> {
        self.network_acl_association_id.as_deref()
    }
    /// <p>The identifier of the network ACL.</p>
    pub fn network_acl_id(&self) -> ::std::option::Option<&str> {
        self.network_acl_id.as_deref()
    }
    /// <p>The identifier of the subnet that is associated with the network ACL.</p>
    pub fn subnet_id(&self) -> ::std::option::Option<&str> {
        self.subnet_id.as_deref()
    }
}
impl AwsEc2NetworkAclAssociation {
    /// Creates a new builder-style object to manufacture [`AwsEc2NetworkAclAssociation`](crate::types::AwsEc2NetworkAclAssociation).
    pub fn builder() -> crate::types::builders::AwsEc2NetworkAclAssociationBuilder {
        crate::types::builders::AwsEc2NetworkAclAssociationBuilder::default()
    }
}

/// A builder for [`AwsEc2NetworkAclAssociation`](crate::types::AwsEc2NetworkAclAssociation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEc2NetworkAclAssociationBuilder {
    pub(crate) network_acl_association_id: ::std::option::Option<::std::string::String>,
    pub(crate) network_acl_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_id: ::std::option::Option<::std::string::String>,
}
impl AwsEc2NetworkAclAssociationBuilder {
    /// <p>The identifier of the association between the network ACL and the subnet.</p>
    pub fn network_acl_association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_acl_association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the association between the network ACL and the subnet.</p>
    pub fn set_network_acl_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_acl_association_id = input;
        self
    }
    /// <p>The identifier of the association between the network ACL and the subnet.</p>
    pub fn get_network_acl_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_acl_association_id
    }
    /// <p>The identifier of the network ACL.</p>
    pub fn network_acl_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_acl_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the network ACL.</p>
    pub fn set_network_acl_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_acl_id = input;
        self
    }
    /// <p>The identifier of the network ACL.</p>
    pub fn get_network_acl_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_acl_id
    }
    /// <p>The identifier of the subnet that is associated with the network ACL.</p>
    pub fn subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the subnet that is associated with the network ACL.</p>
    pub fn set_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_id = input;
        self
    }
    /// <p>The identifier of the subnet that is associated with the network ACL.</p>
    pub fn get_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_id
    }
    /// Consumes the builder and constructs a [`AwsEc2NetworkAclAssociation`](crate::types::AwsEc2NetworkAclAssociation).
    pub fn build(self) -> crate::types::AwsEc2NetworkAclAssociation {
        crate::types::AwsEc2NetworkAclAssociation {
            network_acl_association_id: self.network_acl_association_id,
            network_acl_id: self.network_acl_id,
            subnet_id: self.subnet_id,
        }
    }
}
