// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AdminAddUserToGroupInput {
    /// <p>The ID of the user pool that contains the group that you want to add the user to.</p>
    pub user_pool_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    pub username: ::std::option::Option<::std::string::String>,
    /// <p>The name of the group that you want to add your user to.</p>
    pub group_name: ::std::option::Option<::std::string::String>,
}
impl AdminAddUserToGroupInput {
    /// <p>The ID of the user pool that contains the group that you want to add the user to.</p>
    pub fn user_pool_id(&self) -> ::std::option::Option<&str> {
        self.user_pool_id.as_deref()
    }
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
    /// <p>The name of the group that you want to add your user to.</p>
    pub fn group_name(&self) -> ::std::option::Option<&str> {
        self.group_name.as_deref()
    }
}
impl ::std::fmt::Debug for AdminAddUserToGroupInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AdminAddUserToGroupInput");
        formatter.field("user_pool_id", &self.user_pool_id);
        formatter.field("username", &"*** Sensitive Data Redacted ***");
        formatter.field("group_name", &self.group_name);
        formatter.finish()
    }
}
impl AdminAddUserToGroupInput {
    /// Creates a new builder-style object to manufacture [`AdminAddUserToGroupInput`](crate::operation::admin_add_user_to_group::AdminAddUserToGroupInput).
    pub fn builder() -> crate::operation::admin_add_user_to_group::builders::AdminAddUserToGroupInputBuilder {
        crate::operation::admin_add_user_to_group::builders::AdminAddUserToGroupInputBuilder::default()
    }
}

/// A builder for [`AdminAddUserToGroupInput`](crate::operation::admin_add_user_to_group::AdminAddUserToGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AdminAddUserToGroupInputBuilder {
    pub(crate) user_pool_id: ::std::option::Option<::std::string::String>,
    pub(crate) username: ::std::option::Option<::std::string::String>,
    pub(crate) group_name: ::std::option::Option<::std::string::String>,
}
impl AdminAddUserToGroupInputBuilder {
    /// <p>The ID of the user pool that contains the group that you want to add the user to.</p>
    /// This field is required.
    pub fn user_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the user pool that contains the group that you want to add the user to.</p>
    pub fn set_user_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_id = input;
        self
    }
    /// <p>The ID of the user pool that contains the group that you want to add the user to.</p>
    pub fn get_user_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_id
    }
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    /// This field is required.
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// <p>The name of the group that you want to add your user to.</p>
    /// This field is required.
    pub fn group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the group that you want to add your user to.</p>
    pub fn set_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_name = input;
        self
    }
    /// <p>The name of the group that you want to add your user to.</p>
    pub fn get_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_name
    }
    /// Consumes the builder and constructs a [`AdminAddUserToGroupInput`](crate::operation::admin_add_user_to_group::AdminAddUserToGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::admin_add_user_to_group::AdminAddUserToGroupInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::admin_add_user_to_group::AdminAddUserToGroupInput {
            user_pool_id: self.user_pool_id,
            username: self.username,
            group_name: self.group_name,
        })
    }
}
impl ::std::fmt::Debug for AdminAddUserToGroupInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AdminAddUserToGroupInputBuilder");
        formatter.field("user_pool_id", &self.user_pool_id);
        formatter.field("username", &"*** Sensitive Data Redacted ***");
        formatter.field("group_name", &self.group_name);
        formatter.finish()
    }
}
