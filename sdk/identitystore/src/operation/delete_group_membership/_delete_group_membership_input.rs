// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteGroupMembershipInput {
    /// <p>The globally unique identifier for the identity store.</p>
    pub identity_store_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for a <code>GroupMembership</code> in an identity store.</p>
    pub membership_id: ::std::option::Option<::std::string::String>,
}
impl DeleteGroupMembershipInput {
    /// <p>The globally unique identifier for the identity store.</p>
    pub fn identity_store_id(&self) -> ::std::option::Option<&str> {
        self.identity_store_id.as_deref()
    }
    /// <p>The identifier for a <code>GroupMembership</code> in an identity store.</p>
    pub fn membership_id(&self) -> ::std::option::Option<&str> {
        self.membership_id.as_deref()
    }
}
impl DeleteGroupMembershipInput {
    /// Creates a new builder-style object to manufacture [`DeleteGroupMembershipInput`](crate::operation::delete_group_membership::DeleteGroupMembershipInput).
    pub fn builder() -> crate::operation::delete_group_membership::builders::DeleteGroupMembershipInputBuilder {
        crate::operation::delete_group_membership::builders::DeleteGroupMembershipInputBuilder::default()
    }
}

/// A builder for [`DeleteGroupMembershipInput`](crate::operation::delete_group_membership::DeleteGroupMembershipInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteGroupMembershipInputBuilder {
    pub(crate) identity_store_id: ::std::option::Option<::std::string::String>,
    pub(crate) membership_id: ::std::option::Option<::std::string::String>,
}
impl DeleteGroupMembershipInputBuilder {
    /// <p>The globally unique identifier for the identity store.</p>
    /// This field is required.
    pub fn identity_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The globally unique identifier for the identity store.</p>
    pub fn set_identity_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_store_id = input;
        self
    }
    /// <p>The globally unique identifier for the identity store.</p>
    pub fn get_identity_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_store_id
    }
    /// <p>The identifier for a <code>GroupMembership</code> in an identity store.</p>
    /// This field is required.
    pub fn membership_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for a <code>GroupMembership</code> in an identity store.</p>
    pub fn set_membership_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_id = input;
        self
    }
    /// <p>The identifier for a <code>GroupMembership</code> in an identity store.</p>
    pub fn get_membership_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_id
    }
    /// Consumes the builder and constructs a [`DeleteGroupMembershipInput`](crate::operation::delete_group_membership::DeleteGroupMembershipInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_group_membership::DeleteGroupMembershipInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_group_membership::DeleteGroupMembershipInput {
            identity_store_id: self.identity_store_id,
            membership_id: self.membership_id,
        })
    }
}
