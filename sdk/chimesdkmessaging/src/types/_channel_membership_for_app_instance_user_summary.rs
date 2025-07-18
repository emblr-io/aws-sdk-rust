// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary of the channel membership details of an <code>AppInstanceUser</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChannelMembershipForAppInstanceUserSummary {
    /// <p>Returns the channel data for an <code>AppInstance</code>.</p>
    pub channel_summary: ::std::option::Option<crate::types::ChannelSummary>,
    /// <p>Returns the channel membership data for an <code>AppInstance</code>.</p>
    pub app_instance_user_membership_summary: ::std::option::Option<crate::types::AppInstanceUserMembershipSummary>,
}
impl ChannelMembershipForAppInstanceUserSummary {
    /// <p>Returns the channel data for an <code>AppInstance</code>.</p>
    pub fn channel_summary(&self) -> ::std::option::Option<&crate::types::ChannelSummary> {
        self.channel_summary.as_ref()
    }
    /// <p>Returns the channel membership data for an <code>AppInstance</code>.</p>
    pub fn app_instance_user_membership_summary(&self) -> ::std::option::Option<&crate::types::AppInstanceUserMembershipSummary> {
        self.app_instance_user_membership_summary.as_ref()
    }
}
impl ChannelMembershipForAppInstanceUserSummary {
    /// Creates a new builder-style object to manufacture [`ChannelMembershipForAppInstanceUserSummary`](crate::types::ChannelMembershipForAppInstanceUserSummary).
    pub fn builder() -> crate::types::builders::ChannelMembershipForAppInstanceUserSummaryBuilder {
        crate::types::builders::ChannelMembershipForAppInstanceUserSummaryBuilder::default()
    }
}

/// A builder for [`ChannelMembershipForAppInstanceUserSummary`](crate::types::ChannelMembershipForAppInstanceUserSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChannelMembershipForAppInstanceUserSummaryBuilder {
    pub(crate) channel_summary: ::std::option::Option<crate::types::ChannelSummary>,
    pub(crate) app_instance_user_membership_summary: ::std::option::Option<crate::types::AppInstanceUserMembershipSummary>,
}
impl ChannelMembershipForAppInstanceUserSummaryBuilder {
    /// <p>Returns the channel data for an <code>AppInstance</code>.</p>
    pub fn channel_summary(mut self, input: crate::types::ChannelSummary) -> Self {
        self.channel_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns the channel data for an <code>AppInstance</code>.</p>
    pub fn set_channel_summary(mut self, input: ::std::option::Option<crate::types::ChannelSummary>) -> Self {
        self.channel_summary = input;
        self
    }
    /// <p>Returns the channel data for an <code>AppInstance</code>.</p>
    pub fn get_channel_summary(&self) -> &::std::option::Option<crate::types::ChannelSummary> {
        &self.channel_summary
    }
    /// <p>Returns the channel membership data for an <code>AppInstance</code>.</p>
    pub fn app_instance_user_membership_summary(mut self, input: crate::types::AppInstanceUserMembershipSummary) -> Self {
        self.app_instance_user_membership_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns the channel membership data for an <code>AppInstance</code>.</p>
    pub fn set_app_instance_user_membership_summary(mut self, input: ::std::option::Option<crate::types::AppInstanceUserMembershipSummary>) -> Self {
        self.app_instance_user_membership_summary = input;
        self
    }
    /// <p>Returns the channel membership data for an <code>AppInstance</code>.</p>
    pub fn get_app_instance_user_membership_summary(&self) -> &::std::option::Option<crate::types::AppInstanceUserMembershipSummary> {
        &self.app_instance_user_membership_summary
    }
    /// Consumes the builder and constructs a [`ChannelMembershipForAppInstanceUserSummary`](crate::types::ChannelMembershipForAppInstanceUserSummary).
    pub fn build(self) -> crate::types::ChannelMembershipForAppInstanceUserSummary {
        crate::types::ChannelMembershipForAppInstanceUserSummary {
            channel_summary: self.channel_summary,
            app_instance_user_membership_summary: self.app_instance_user_membership_summary,
        }
    }
}
