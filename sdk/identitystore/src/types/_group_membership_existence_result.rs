// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates whether a resource is a member of a group in the identity store.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GroupMembershipExistenceResult {
    /// <p>The identifier for a group in the identity store.</p>
    pub group_id: ::std::option::Option<::std::string::String>,
    /// <p>An object that contains the identifier of a group member. Setting the <code>UserID</code> field to the specific identifier for a user indicates that the user is a member of the group.</p>
    pub member_id: ::std::option::Option<crate::types::MemberId>,
    /// <p>Indicates whether a membership relation exists or not.</p>
    pub membership_exists: bool,
}
impl GroupMembershipExistenceResult {
    /// <p>The identifier for a group in the identity store.</p>
    pub fn group_id(&self) -> ::std::option::Option<&str> {
        self.group_id.as_deref()
    }
    /// <p>An object that contains the identifier of a group member. Setting the <code>UserID</code> field to the specific identifier for a user indicates that the user is a member of the group.</p>
    pub fn member_id(&self) -> ::std::option::Option<&crate::types::MemberId> {
        self.member_id.as_ref()
    }
    /// <p>Indicates whether a membership relation exists or not.</p>
    pub fn membership_exists(&self) -> bool {
        self.membership_exists
    }
}
impl ::std::fmt::Debug for GroupMembershipExistenceResult {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GroupMembershipExistenceResult");
        formatter.field("group_id", &self.group_id);
        formatter.field("member_id", &self.member_id);
        formatter.field("membership_exists", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl GroupMembershipExistenceResult {
    /// Creates a new builder-style object to manufacture [`GroupMembershipExistenceResult`](crate::types::GroupMembershipExistenceResult).
    pub fn builder() -> crate::types::builders::GroupMembershipExistenceResultBuilder {
        crate::types::builders::GroupMembershipExistenceResultBuilder::default()
    }
}

/// A builder for [`GroupMembershipExistenceResult`](crate::types::GroupMembershipExistenceResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GroupMembershipExistenceResultBuilder {
    pub(crate) group_id: ::std::option::Option<::std::string::String>,
    pub(crate) member_id: ::std::option::Option<crate::types::MemberId>,
    pub(crate) membership_exists: ::std::option::Option<bool>,
}
impl GroupMembershipExistenceResultBuilder {
    /// <p>The identifier for a group in the identity store.</p>
    pub fn group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for a group in the identity store.</p>
    pub fn set_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_id = input;
        self
    }
    /// <p>The identifier for a group in the identity store.</p>
    pub fn get_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_id
    }
    /// <p>An object that contains the identifier of a group member. Setting the <code>UserID</code> field to the specific identifier for a user indicates that the user is a member of the group.</p>
    pub fn member_id(mut self, input: crate::types::MemberId) -> Self {
        self.member_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains the identifier of a group member. Setting the <code>UserID</code> field to the specific identifier for a user indicates that the user is a member of the group.</p>
    pub fn set_member_id(mut self, input: ::std::option::Option<crate::types::MemberId>) -> Self {
        self.member_id = input;
        self
    }
    /// <p>An object that contains the identifier of a group member. Setting the <code>UserID</code> field to the specific identifier for a user indicates that the user is a member of the group.</p>
    pub fn get_member_id(&self) -> &::std::option::Option<crate::types::MemberId> {
        &self.member_id
    }
    /// <p>Indicates whether a membership relation exists or not.</p>
    pub fn membership_exists(mut self, input: bool) -> Self {
        self.membership_exists = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether a membership relation exists or not.</p>
    pub fn set_membership_exists(mut self, input: ::std::option::Option<bool>) -> Self {
        self.membership_exists = input;
        self
    }
    /// <p>Indicates whether a membership relation exists or not.</p>
    pub fn get_membership_exists(&self) -> &::std::option::Option<bool> {
        &self.membership_exists
    }
    /// Consumes the builder and constructs a [`GroupMembershipExistenceResult`](crate::types::GroupMembershipExistenceResult).
    pub fn build(self) -> crate::types::GroupMembershipExistenceResult {
        crate::types::GroupMembershipExistenceResult {
            group_id: self.group_id,
            member_id: self.member_id,
            membership_exists: self.membership_exists.unwrap_or_default(),
        }
    }
}
impl ::std::fmt::Debug for GroupMembershipExistenceResultBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GroupMembershipExistenceResultBuilder");
        formatter.field("group_id", &self.group_id);
        formatter.field("member_id", &self.member_id);
        formatter.field("membership_exists", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
