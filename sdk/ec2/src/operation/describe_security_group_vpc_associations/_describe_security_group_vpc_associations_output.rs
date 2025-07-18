// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeSecurityGroupVpcAssociationsOutput {
    /// <p>The security group VPC associations.</p>
    pub security_group_vpc_associations: ::std::option::Option<::std::vec::Vec<crate::types::SecurityGroupVpcAssociation>>,
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeSecurityGroupVpcAssociationsOutput {
    /// <p>The security group VPC associations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_vpc_associations.is_none()`.
    pub fn security_group_vpc_associations(&self) -> &[crate::types::SecurityGroupVpcAssociation] {
        self.security_group_vpc_associations.as_deref().unwrap_or_default()
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeSecurityGroupVpcAssociationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeSecurityGroupVpcAssociationsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeSecurityGroupVpcAssociationsOutput`](crate::operation::describe_security_group_vpc_associations::DescribeSecurityGroupVpcAssociationsOutput).
    pub fn builder() -> crate::operation::describe_security_group_vpc_associations::builders::DescribeSecurityGroupVpcAssociationsOutputBuilder {
        crate::operation::describe_security_group_vpc_associations::builders::DescribeSecurityGroupVpcAssociationsOutputBuilder::default()
    }
}

/// A builder for [`DescribeSecurityGroupVpcAssociationsOutput`](crate::operation::describe_security_group_vpc_associations::DescribeSecurityGroupVpcAssociationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeSecurityGroupVpcAssociationsOutputBuilder {
    pub(crate) security_group_vpc_associations: ::std::option::Option<::std::vec::Vec<crate::types::SecurityGroupVpcAssociation>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeSecurityGroupVpcAssociationsOutputBuilder {
    /// Appends an item to `security_group_vpc_associations`.
    ///
    /// To override the contents of this collection use [`set_security_group_vpc_associations`](Self::set_security_group_vpc_associations).
    ///
    /// <p>The security group VPC associations.</p>
    pub fn security_group_vpc_associations(mut self, input: crate::types::SecurityGroupVpcAssociation) -> Self {
        let mut v = self.security_group_vpc_associations.unwrap_or_default();
        v.push(input);
        self.security_group_vpc_associations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The security group VPC associations.</p>
    pub fn set_security_group_vpc_associations(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::SecurityGroupVpcAssociation>>,
    ) -> Self {
        self.security_group_vpc_associations = input;
        self
    }
    /// <p>The security group VPC associations.</p>
    pub fn get_security_group_vpc_associations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SecurityGroupVpcAssociation>> {
        &self.security_group_vpc_associations
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeSecurityGroupVpcAssociationsOutput`](crate::operation::describe_security_group_vpc_associations::DescribeSecurityGroupVpcAssociationsOutput).
    pub fn build(self) -> crate::operation::describe_security_group_vpc_associations::DescribeSecurityGroupVpcAssociationsOutput {
        crate::operation::describe_security_group_vpc_associations::DescribeSecurityGroupVpcAssociationsOutput {
            security_group_vpc_associations: self.security_group_vpc_associations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
