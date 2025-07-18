// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InviteUsersOutput {
    /// <p>The email invitation details.</p>
    pub invites: ::std::option::Option<::std::vec::Vec<crate::types::Invite>>,
    _request_id: Option<String>,
}
impl InviteUsersOutput {
    /// <p>The email invitation details.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.invites.is_none()`.
    pub fn invites(&self) -> &[crate::types::Invite] {
        self.invites.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for InviteUsersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl InviteUsersOutput {
    /// Creates a new builder-style object to manufacture [`InviteUsersOutput`](crate::operation::invite_users::InviteUsersOutput).
    pub fn builder() -> crate::operation::invite_users::builders::InviteUsersOutputBuilder {
        crate::operation::invite_users::builders::InviteUsersOutputBuilder::default()
    }
}

/// A builder for [`InviteUsersOutput`](crate::operation::invite_users::InviteUsersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InviteUsersOutputBuilder {
    pub(crate) invites: ::std::option::Option<::std::vec::Vec<crate::types::Invite>>,
    _request_id: Option<String>,
}
impl InviteUsersOutputBuilder {
    /// Appends an item to `invites`.
    ///
    /// To override the contents of this collection use [`set_invites`](Self::set_invites).
    ///
    /// <p>The email invitation details.</p>
    pub fn invites(mut self, input: crate::types::Invite) -> Self {
        let mut v = self.invites.unwrap_or_default();
        v.push(input);
        self.invites = ::std::option::Option::Some(v);
        self
    }
    /// <p>The email invitation details.</p>
    pub fn set_invites(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Invite>>) -> Self {
        self.invites = input;
        self
    }
    /// <p>The email invitation details.</p>
    pub fn get_invites(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Invite>> {
        &self.invites
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`InviteUsersOutput`](crate::operation::invite_users::InviteUsersOutput).
    pub fn build(self) -> crate::operation::invite_users::InviteUsersOutput {
        crate::operation::invite_users::InviteUsersOutput {
            invites: self.invites,
            _request_id: self._request_id,
        }
    }
}
