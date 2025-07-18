// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Filtering options for <i>ListUsers</i> operation. This is only used as input to Operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ListUsersFilters {
    /// <p>Filters only users with the provided username prefix.</p>
    pub username_prefix: ::std::option::Option<::std::string::String>,
    /// <p>Filters only users with the provided display name prefix.</p>
    pub display_name_prefix: ::std::option::Option<::std::string::String>,
    /// <p>Filters only users with the provided email prefix.</p>
    pub primary_email_prefix: ::std::option::Option<::std::string::String>,
    /// <p>Filters only users with the provided state.</p>
    pub state: ::std::option::Option<crate::types::EntityState>,
    /// <p>Filters only users with the ID from the IAM Identity Center.</p>
    pub identity_provider_user_id_prefix: ::std::option::Option<::std::string::String>,
}
impl ListUsersFilters {
    /// <p>Filters only users with the provided username prefix.</p>
    pub fn username_prefix(&self) -> ::std::option::Option<&str> {
        self.username_prefix.as_deref()
    }
    /// <p>Filters only users with the provided display name prefix.</p>
    pub fn display_name_prefix(&self) -> ::std::option::Option<&str> {
        self.display_name_prefix.as_deref()
    }
    /// <p>Filters only users with the provided email prefix.</p>
    pub fn primary_email_prefix(&self) -> ::std::option::Option<&str> {
        self.primary_email_prefix.as_deref()
    }
    /// <p>Filters only users with the provided state.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::EntityState> {
        self.state.as_ref()
    }
    /// <p>Filters only users with the ID from the IAM Identity Center.</p>
    pub fn identity_provider_user_id_prefix(&self) -> ::std::option::Option<&str> {
        self.identity_provider_user_id_prefix.as_deref()
    }
}
impl ::std::fmt::Debug for ListUsersFilters {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListUsersFilters");
        formatter.field("username_prefix", &self.username_prefix);
        formatter.field("display_name_prefix", &"*** Sensitive Data Redacted ***");
        formatter.field("primary_email_prefix", &self.primary_email_prefix);
        formatter.field("state", &self.state);
        formatter.field("identity_provider_user_id_prefix", &self.identity_provider_user_id_prefix);
        formatter.finish()
    }
}
impl ListUsersFilters {
    /// Creates a new builder-style object to manufacture [`ListUsersFilters`](crate::types::ListUsersFilters).
    pub fn builder() -> crate::types::builders::ListUsersFiltersBuilder {
        crate::types::builders::ListUsersFiltersBuilder::default()
    }
}

/// A builder for [`ListUsersFilters`](crate::types::ListUsersFilters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ListUsersFiltersBuilder {
    pub(crate) username_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) display_name_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) primary_email_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::EntityState>,
    pub(crate) identity_provider_user_id_prefix: ::std::option::Option<::std::string::String>,
}
impl ListUsersFiltersBuilder {
    /// <p>Filters only users with the provided username prefix.</p>
    pub fn username_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters only users with the provided username prefix.</p>
    pub fn set_username_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username_prefix = input;
        self
    }
    /// <p>Filters only users with the provided username prefix.</p>
    pub fn get_username_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.username_prefix
    }
    /// <p>Filters only users with the provided display name prefix.</p>
    pub fn display_name_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters only users with the provided display name prefix.</p>
    pub fn set_display_name_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name_prefix = input;
        self
    }
    /// <p>Filters only users with the provided display name prefix.</p>
    pub fn get_display_name_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name_prefix
    }
    /// <p>Filters only users with the provided email prefix.</p>
    pub fn primary_email_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.primary_email_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters only users with the provided email prefix.</p>
    pub fn set_primary_email_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.primary_email_prefix = input;
        self
    }
    /// <p>Filters only users with the provided email prefix.</p>
    pub fn get_primary_email_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.primary_email_prefix
    }
    /// <p>Filters only users with the provided state.</p>
    pub fn state(mut self, input: crate::types::EntityState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters only users with the provided state.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::EntityState>) -> Self {
        self.state = input;
        self
    }
    /// <p>Filters only users with the provided state.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::EntityState> {
        &self.state
    }
    /// <p>Filters only users with the ID from the IAM Identity Center.</p>
    pub fn identity_provider_user_id_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_provider_user_id_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters only users with the ID from the IAM Identity Center.</p>
    pub fn set_identity_provider_user_id_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_provider_user_id_prefix = input;
        self
    }
    /// <p>Filters only users with the ID from the IAM Identity Center.</p>
    pub fn get_identity_provider_user_id_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_provider_user_id_prefix
    }
    /// Consumes the builder and constructs a [`ListUsersFilters`](crate::types::ListUsersFilters).
    pub fn build(self) -> crate::types::ListUsersFilters {
        crate::types::ListUsersFilters {
            username_prefix: self.username_prefix,
            display_name_prefix: self.display_name_prefix,
            primary_email_prefix: self.primary_email_prefix,
            state: self.state,
            identity_provider_user_id_prefix: self.identity_provider_user_id_prefix,
        }
    }
}
impl ::std::fmt::Debug for ListUsersFiltersBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListUsersFiltersBuilder");
        formatter.field("username_prefix", &self.username_prefix);
        formatter.field("display_name_prefix", &"*** Sensitive Data Redacted ***");
        formatter.field("primary_email_prefix", &self.primary_email_prefix);
        formatter.field("state", &self.state);
        formatter.field("identity_provider_user_id_prefix", &self.identity_provider_user_id_prefix);
        formatter.finish()
    }
}
