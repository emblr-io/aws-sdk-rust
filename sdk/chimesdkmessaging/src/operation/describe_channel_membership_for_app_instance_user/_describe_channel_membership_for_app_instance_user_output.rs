// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeChannelMembershipForAppInstanceUserOutput {
    /// <p>The channel to which a user belongs.</p>
    pub channel_membership: ::std::option::Option<crate::types::ChannelMembershipForAppInstanceUserSummary>,
    _request_id: Option<String>,
}
impl DescribeChannelMembershipForAppInstanceUserOutput {
    /// <p>The channel to which a user belongs.</p>
    pub fn channel_membership(&self) -> ::std::option::Option<&crate::types::ChannelMembershipForAppInstanceUserSummary> {
        self.channel_membership.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeChannelMembershipForAppInstanceUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeChannelMembershipForAppInstanceUserOutput {
    /// Creates a new builder-style object to manufacture [`DescribeChannelMembershipForAppInstanceUserOutput`](crate::operation::describe_channel_membership_for_app_instance_user::DescribeChannelMembershipForAppInstanceUserOutput).
    pub fn builder(
    ) -> crate::operation::describe_channel_membership_for_app_instance_user::builders::DescribeChannelMembershipForAppInstanceUserOutputBuilder {
        crate::operation::describe_channel_membership_for_app_instance_user::builders::DescribeChannelMembershipForAppInstanceUserOutputBuilder::default()
    }
}

/// A builder for [`DescribeChannelMembershipForAppInstanceUserOutput`](crate::operation::describe_channel_membership_for_app_instance_user::DescribeChannelMembershipForAppInstanceUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeChannelMembershipForAppInstanceUserOutputBuilder {
    pub(crate) channel_membership: ::std::option::Option<crate::types::ChannelMembershipForAppInstanceUserSummary>,
    _request_id: Option<String>,
}
impl DescribeChannelMembershipForAppInstanceUserOutputBuilder {
    /// <p>The channel to which a user belongs.</p>
    pub fn channel_membership(mut self, input: crate::types::ChannelMembershipForAppInstanceUserSummary) -> Self {
        self.channel_membership = ::std::option::Option::Some(input);
        self
    }
    /// <p>The channel to which a user belongs.</p>
    pub fn set_channel_membership(mut self, input: ::std::option::Option<crate::types::ChannelMembershipForAppInstanceUserSummary>) -> Self {
        self.channel_membership = input;
        self
    }
    /// <p>The channel to which a user belongs.</p>
    pub fn get_channel_membership(&self) -> &::std::option::Option<crate::types::ChannelMembershipForAppInstanceUserSummary> {
        &self.channel_membership
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeChannelMembershipForAppInstanceUserOutput`](crate::operation::describe_channel_membership_for_app_instance_user::DescribeChannelMembershipForAppInstanceUserOutput).
    pub fn build(self) -> crate::operation::describe_channel_membership_for_app_instance_user::DescribeChannelMembershipForAppInstanceUserOutput {
        crate::operation::describe_channel_membership_for_app_instance_user::DescribeChannelMembershipForAppInstanceUserOutput {
            channel_membership: self.channel_membership,
            _request_id: self._request_id,
        }
    }
}
