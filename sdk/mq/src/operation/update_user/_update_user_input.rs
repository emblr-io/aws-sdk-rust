// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Updates the information for an ActiveMQ user.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateUserInput {
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub broker_id: ::std::option::Option<::std::string::String>,
    /// <p>Enables access to the the ActiveMQ Web Console for the ActiveMQ user.</p>
    pub console_access: ::std::option::Option<bool>,
    /// <p>The list of groups (20 maximum) to which the ActiveMQ user belongs. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The password of the user. This value must be at least 12 characters long, must contain at least 4 unique characters, and must not contain commas, colons, or equal signs (,:=).</p>
    pub password: ::std::option::Option<::std::string::String>,
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub username: ::std::option::Option<::std::string::String>,
    /// <p>Defines whether the user is intended for data replication.</p>
    pub replication_user: ::std::option::Option<bool>,
}
impl UpdateUserInput {
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn broker_id(&self) -> ::std::option::Option<&str> {
        self.broker_id.as_deref()
    }
    /// <p>Enables access to the the ActiveMQ Web Console for the ActiveMQ user.</p>
    pub fn console_access(&self) -> ::std::option::Option<bool> {
        self.console_access
    }
    /// <p>The list of groups (20 maximum) to which the ActiveMQ user belongs. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.groups.is_none()`.
    pub fn groups(&self) -> &[::std::string::String] {
        self.groups.as_deref().unwrap_or_default()
    }
    /// <p>The password of the user. This value must be at least 12 characters long, must contain at least 4 unique characters, and must not contain commas, colons, or equal signs (,:=).</p>
    pub fn password(&self) -> ::std::option::Option<&str> {
        self.password.as_deref()
    }
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
    /// <p>Defines whether the user is intended for data replication.</p>
    pub fn replication_user(&self) -> ::std::option::Option<bool> {
        self.replication_user
    }
}
impl UpdateUserInput {
    /// Creates a new builder-style object to manufacture [`UpdateUserInput`](crate::operation::update_user::UpdateUserInput).
    pub fn builder() -> crate::operation::update_user::builders::UpdateUserInputBuilder {
        crate::operation::update_user::builders::UpdateUserInputBuilder::default()
    }
}

/// A builder for [`UpdateUserInput`](crate::operation::update_user::UpdateUserInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateUserInputBuilder {
    pub(crate) broker_id: ::std::option::Option<::std::string::String>,
    pub(crate) console_access: ::std::option::Option<bool>,
    pub(crate) groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) password: ::std::option::Option<::std::string::String>,
    pub(crate) username: ::std::option::Option<::std::string::String>,
    pub(crate) replication_user: ::std::option::Option<bool>,
}
impl UpdateUserInputBuilder {
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    /// This field is required.
    pub fn broker_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.broker_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn set_broker_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.broker_id = input;
        self
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn get_broker_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.broker_id
    }
    /// <p>Enables access to the the ActiveMQ Web Console for the ActiveMQ user.</p>
    pub fn console_access(mut self, input: bool) -> Self {
        self.console_access = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables access to the the ActiveMQ Web Console for the ActiveMQ user.</p>
    pub fn set_console_access(mut self, input: ::std::option::Option<bool>) -> Self {
        self.console_access = input;
        self
    }
    /// <p>Enables access to the the ActiveMQ Web Console for the ActiveMQ user.</p>
    pub fn get_console_access(&self) -> &::std::option::Option<bool> {
        &self.console_access
    }
    /// Appends an item to `groups`.
    ///
    /// To override the contents of this collection use [`set_groups`](Self::set_groups).
    ///
    /// <p>The list of groups (20 maximum) to which the ActiveMQ user belongs. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub fn groups(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.groups.unwrap_or_default();
        v.push(input.into());
        self.groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of groups (20 maximum) to which the ActiveMQ user belongs. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub fn set_groups(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.groups = input;
        self
    }
    /// <p>The list of groups (20 maximum) to which the ActiveMQ user belongs. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub fn get_groups(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.groups
    }
    /// <p>The password of the user. This value must be at least 12 characters long, must contain at least 4 unique characters, and must not contain commas, colons, or equal signs (,:=).</p>
    pub fn password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The password of the user. This value must be at least 12 characters long, must contain at least 4 unique characters, and must not contain commas, colons, or equal signs (,:=).</p>
    pub fn set_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password = input;
        self
    }
    /// <p>The password of the user. This value must be at least 12 characters long, must contain at least 4 unique characters, and must not contain commas, colons, or equal signs (,:=).</p>
    pub fn get_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.password
    }
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    /// This field is required.
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// <p>Defines whether the user is intended for data replication.</p>
    pub fn replication_user(mut self, input: bool) -> Self {
        self.replication_user = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines whether the user is intended for data replication.</p>
    pub fn set_replication_user(mut self, input: ::std::option::Option<bool>) -> Self {
        self.replication_user = input;
        self
    }
    /// <p>Defines whether the user is intended for data replication.</p>
    pub fn get_replication_user(&self) -> &::std::option::Option<bool> {
        &self.replication_user
    }
    /// Consumes the builder and constructs a [`UpdateUserInput`](crate::operation::update_user::UpdateUserInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::update_user::UpdateUserInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_user::UpdateUserInput {
            broker_id: self.broker_id,
            console_access: self.console_access,
            groups: self.groups,
            password: self.password,
            username: self.username,
            replication_user: self.replication_user,
        })
    }
}
