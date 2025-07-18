// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSecurityGroupsForVpcOutput {
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The security group that can be used by interfaces in the VPC.</p>
    pub security_group_for_vpcs: ::std::option::Option<::std::vec::Vec<crate::types::SecurityGroupForVpc>>,
    _request_id: Option<String>,
}
impl GetSecurityGroupsForVpcOutput {
    /// <p>The token to include in another request to get the next page of items. This value is <code>null</code> when there are no more items to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The security group that can be used by interfaces in the VPC.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_for_vpcs.is_none()`.
    pub fn security_group_for_vpcs(&self) -> &[crate::types::SecurityGroupForVpc] {
        self.security_group_for_vpcs.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetSecurityGroupsForVpcOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSecurityGroupsForVpcOutput {
    /// Creates a new builder-style object to manufacture [`GetSecurityGroupsForVpcOutput`](crate::operation::get_security_groups_for_vpc::GetSecurityGroupsForVpcOutput).
    pub fn builder() -> crate::operation::get_security_groups_for_vpc::builders::GetSecurityGroupsForVpcOutputBuilder {
        crate::operation::get_security_groups_for_vpc::builders::GetSecurityGroupsForVpcOutputBuilder::default()
    }
}

/// A builder for [`GetSecurityGroupsForVpcOutput`](crate::operation::get_security_groups_for_vpc::GetSecurityGroupsForVpcOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSecurityGroupsForVpcOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) security_group_for_vpcs: ::std::option::Option<::std::vec::Vec<crate::types::SecurityGroupForVpc>>,
    _request_id: Option<String>,
}
impl GetSecurityGroupsForVpcOutputBuilder {
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
    /// Appends an item to `security_group_for_vpcs`.
    ///
    /// To override the contents of this collection use [`set_security_group_for_vpcs`](Self::set_security_group_for_vpcs).
    ///
    /// <p>The security group that can be used by interfaces in the VPC.</p>
    pub fn security_group_for_vpcs(mut self, input: crate::types::SecurityGroupForVpc) -> Self {
        let mut v = self.security_group_for_vpcs.unwrap_or_default();
        v.push(input);
        self.security_group_for_vpcs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The security group that can be used by interfaces in the VPC.</p>
    pub fn set_security_group_for_vpcs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SecurityGroupForVpc>>) -> Self {
        self.security_group_for_vpcs = input;
        self
    }
    /// <p>The security group that can be used by interfaces in the VPC.</p>
    pub fn get_security_group_for_vpcs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SecurityGroupForVpc>> {
        &self.security_group_for_vpcs
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSecurityGroupsForVpcOutput`](crate::operation::get_security_groups_for_vpc::GetSecurityGroupsForVpcOutput).
    pub fn build(self) -> crate::operation::get_security_groups_for_vpc::GetSecurityGroupsForVpcOutput {
        crate::operation::get_security_groups_for_vpc::GetSecurityGroupsForVpcOutput {
            next_token: self.next_token,
            security_group_for_vpcs: self.security_group_for_vpcs,
            _request_id: self._request_id,
        }
    }
}
