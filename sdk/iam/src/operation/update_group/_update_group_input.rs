// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateGroupInput {
    /// <p>Name of the IAM group to update. If you're changing the name of the group, this is the original name.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub group_name: ::std::option::Option<::std::string::String>,
    /// <p>New path for the IAM group. Only include this if changing the group's path.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub new_path: ::std::option::Option<::std::string::String>,
    /// <p>New name for the IAM group. Only include this if changing the group's name.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    pub new_group_name: ::std::option::Option<::std::string::String>,
}
impl UpdateGroupInput {
    /// <p>Name of the IAM group to update. If you're changing the name of the group, this is the original name.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn group_name(&self) -> ::std::option::Option<&str> {
        self.group_name.as_deref()
    }
    /// <p>New path for the IAM group. Only include this if changing the group's path.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub fn new_path(&self) -> ::std::option::Option<&str> {
        self.new_path.as_deref()
    }
    /// <p>New name for the IAM group. Only include this if changing the group's name.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    pub fn new_group_name(&self) -> ::std::option::Option<&str> {
        self.new_group_name.as_deref()
    }
}
impl UpdateGroupInput {
    /// Creates a new builder-style object to manufacture [`UpdateGroupInput`](crate::operation::update_group::UpdateGroupInput).
    pub fn builder() -> crate::operation::update_group::builders::UpdateGroupInputBuilder {
        crate::operation::update_group::builders::UpdateGroupInputBuilder::default()
    }
}

/// A builder for [`UpdateGroupInput`](crate::operation::update_group::UpdateGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateGroupInputBuilder {
    pub(crate) group_name: ::std::option::Option<::std::string::String>,
    pub(crate) new_path: ::std::option::Option<::std::string::String>,
    pub(crate) new_group_name: ::std::option::Option<::std::string::String>,
}
impl UpdateGroupInputBuilder {
    /// <p>Name of the IAM group to update. If you're changing the name of the group, this is the original name.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    /// This field is required.
    pub fn group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the IAM group to update. If you're changing the name of the group, this is the original name.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn set_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_name = input;
        self
    }
    /// <p>Name of the IAM group to update. If you're changing the name of the group, this is the original name.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn get_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_name
    }
    /// <p>New path for the IAM group. Only include this if changing the group's path.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub fn new_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>New path for the IAM group. Only include this if changing the group's path.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub fn set_new_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_path = input;
        self
    }
    /// <p>New path for the IAM group. Only include this if changing the group's path.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (<code>\u0021</code>) through the DEL character (<code>\u007F</code>), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub fn get_new_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_path
    }
    /// <p>New name for the IAM group. Only include this if changing the group's name.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    pub fn new_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>New name for the IAM group. Only include this if changing the group's name.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    pub fn set_new_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_group_name = input;
        self
    }
    /// <p>New name for the IAM group. Only include this if changing the group's name.</p>
    /// <p>IAM user, group, role, and policy names must be unique within the account. Names are not distinguished by case. For example, you cannot create resources named both "MyResource" and "myresource".</p>
    pub fn get_new_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_group_name
    }
    /// Consumes the builder and constructs a [`UpdateGroupInput`](crate::operation::update_group::UpdateGroupInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::update_group::UpdateGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_group::UpdateGroupInput {
            group_name: self.group_name,
            new_path: self.new_path,
            new_group_name: self.new_group_name,
        })
    }
}
