// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ListChannelMembershipsForAppInstanceUserOutput {
    /// <p>The information for the requested channel memberships.</p>
    pub channel_memberships: ::std::option::Option<::std::vec::Vec<crate::types::ChannelMembershipForAppInstanceUserSummary>>,
    /// <p>The token passed by previous API calls until all requested users are returned.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListChannelMembershipsForAppInstanceUserOutput {
    /// <p>The information for the requested channel memberships.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.channel_memberships.is_none()`.
    pub fn channel_memberships(&self) -> &[crate::types::ChannelMembershipForAppInstanceUserSummary] {
        self.channel_memberships.as_deref().unwrap_or_default()
    }
    /// <p>The token passed by previous API calls until all requested users are returned.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::std::fmt::Debug for ListChannelMembershipsForAppInstanceUserOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListChannelMembershipsForAppInstanceUserOutput");
        formatter.field("channel_memberships", &self.channel_memberships);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for ListChannelMembershipsForAppInstanceUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListChannelMembershipsForAppInstanceUserOutput {
    /// Creates a new builder-style object to manufacture [`ListChannelMembershipsForAppInstanceUserOutput`](crate::operation::list_channel_memberships_for_app_instance_user::ListChannelMembershipsForAppInstanceUserOutput).
    pub fn builder(
    ) -> crate::operation::list_channel_memberships_for_app_instance_user::builders::ListChannelMembershipsForAppInstanceUserOutputBuilder {
        crate::operation::list_channel_memberships_for_app_instance_user::builders::ListChannelMembershipsForAppInstanceUserOutputBuilder::default()
    }
}

/// A builder for [`ListChannelMembershipsForAppInstanceUserOutput`](crate::operation::list_channel_memberships_for_app_instance_user::ListChannelMembershipsForAppInstanceUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ListChannelMembershipsForAppInstanceUserOutputBuilder {
    pub(crate) channel_memberships: ::std::option::Option<::std::vec::Vec<crate::types::ChannelMembershipForAppInstanceUserSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListChannelMembershipsForAppInstanceUserOutputBuilder {
    /// Appends an item to `channel_memberships`.
    ///
    /// To override the contents of this collection use [`set_channel_memberships`](Self::set_channel_memberships).
    ///
    /// <p>The information for the requested channel memberships.</p>
    pub fn channel_memberships(mut self, input: crate::types::ChannelMembershipForAppInstanceUserSummary) -> Self {
        let mut v = self.channel_memberships.unwrap_or_default();
        v.push(input);
        self.channel_memberships = ::std::option::Option::Some(v);
        self
    }
    /// <p>The information for the requested channel memberships.</p>
    pub fn set_channel_memberships(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ChannelMembershipForAppInstanceUserSummary>>,
    ) -> Self {
        self.channel_memberships = input;
        self
    }
    /// <p>The information for the requested channel memberships.</p>
    pub fn get_channel_memberships(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ChannelMembershipForAppInstanceUserSummary>> {
        &self.channel_memberships
    }
    /// <p>The token passed by previous API calls until all requested users are returned.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token passed by previous API calls until all requested users are returned.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token passed by previous API calls until all requested users are returned.</p>
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
    /// Consumes the builder and constructs a [`ListChannelMembershipsForAppInstanceUserOutput`](crate::operation::list_channel_memberships_for_app_instance_user::ListChannelMembershipsForAppInstanceUserOutput).
    pub fn build(self) -> crate::operation::list_channel_memberships_for_app_instance_user::ListChannelMembershipsForAppInstanceUserOutput {
        crate::operation::list_channel_memberships_for_app_instance_user::ListChannelMembershipsForAppInstanceUserOutput {
            channel_memberships: self.channel_memberships,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for ListChannelMembershipsForAppInstanceUserOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListChannelMembershipsForAppInstanceUserOutputBuilder");
        formatter.field("channel_memberships", &self.channel_memberships);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
