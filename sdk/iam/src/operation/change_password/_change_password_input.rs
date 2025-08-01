// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ChangePasswordInput {
    /// <p>The IAM user's current password.</p>
    pub old_password: ::std::option::Option<::std::string::String>,
    /// <p>The new password. The new password must conform to the Amazon Web Services account's password policy, if one exists.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of characters. That string can include almost any printable ASCII character from the space (<code>\u0020</code>) through the end of the ASCII character range (<code>\u00FF</code>). You can also include the tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) characters. Any of these characters are valid in a password. However, many tools, such as the Amazon Web Services Management Console, might restrict the ability to type certain characters because they have special meaning within that tool.</p>
    pub new_password: ::std::option::Option<::std::string::String>,
}
impl ChangePasswordInput {
    /// <p>The IAM user's current password.</p>
    pub fn old_password(&self) -> ::std::option::Option<&str> {
        self.old_password.as_deref()
    }
    /// <p>The new password. The new password must conform to the Amazon Web Services account's password policy, if one exists.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of characters. That string can include almost any printable ASCII character from the space (<code>\u0020</code>) through the end of the ASCII character range (<code>\u00FF</code>). You can also include the tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) characters. Any of these characters are valid in a password. However, many tools, such as the Amazon Web Services Management Console, might restrict the ability to type certain characters because they have special meaning within that tool.</p>
    pub fn new_password(&self) -> ::std::option::Option<&str> {
        self.new_password.as_deref()
    }
}
impl ::std::fmt::Debug for ChangePasswordInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ChangePasswordInput");
        formatter.field("old_password", &"*** Sensitive Data Redacted ***");
        formatter.field("new_password", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl ChangePasswordInput {
    /// Creates a new builder-style object to manufacture [`ChangePasswordInput`](crate::operation::change_password::ChangePasswordInput).
    pub fn builder() -> crate::operation::change_password::builders::ChangePasswordInputBuilder {
        crate::operation::change_password::builders::ChangePasswordInputBuilder::default()
    }
}

/// A builder for [`ChangePasswordInput`](crate::operation::change_password::ChangePasswordInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ChangePasswordInputBuilder {
    pub(crate) old_password: ::std::option::Option<::std::string::String>,
    pub(crate) new_password: ::std::option::Option<::std::string::String>,
}
impl ChangePasswordInputBuilder {
    /// <p>The IAM user's current password.</p>
    /// This field is required.
    pub fn old_password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.old_password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM user's current password.</p>
    pub fn set_old_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.old_password = input;
        self
    }
    /// <p>The IAM user's current password.</p>
    pub fn get_old_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.old_password
    }
    /// <p>The new password. The new password must conform to the Amazon Web Services account's password policy, if one exists.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of characters. That string can include almost any printable ASCII character from the space (<code>\u0020</code>) through the end of the ASCII character range (<code>\u00FF</code>). You can also include the tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) characters. Any of these characters are valid in a password. However, many tools, such as the Amazon Web Services Management Console, might restrict the ability to type certain characters because they have special meaning within that tool.</p>
    /// This field is required.
    pub fn new_password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new password. The new password must conform to the Amazon Web Services account's password policy, if one exists.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of characters. That string can include almost any printable ASCII character from the space (<code>\u0020</code>) through the end of the ASCII character range (<code>\u00FF</code>). You can also include the tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) characters. Any of these characters are valid in a password. However, many tools, such as the Amazon Web Services Management Console, might restrict the ability to type certain characters because they have special meaning within that tool.</p>
    pub fn set_new_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_password = input;
        self
    }
    /// <p>The new password. The new password must conform to the Amazon Web Services account's password policy, if one exists.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> that is used to validate this parameter is a string of characters. That string can include almost any printable ASCII character from the space (<code>\u0020</code>) through the end of the ASCII character range (<code>\u00FF</code>). You can also include the tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) characters. Any of these characters are valid in a password. However, many tools, such as the Amazon Web Services Management Console, might restrict the ability to type certain characters because they have special meaning within that tool.</p>
    pub fn get_new_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_password
    }
    /// Consumes the builder and constructs a [`ChangePasswordInput`](crate::operation::change_password::ChangePasswordInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::change_password::ChangePasswordInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::change_password::ChangePasswordInput {
            old_password: self.old_password,
            new_password: self.new_password,
        })
    }
}
impl ::std::fmt::Debug for ChangePasswordInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ChangePasswordInputBuilder");
        formatter.field("old_password", &"*** Sensitive Data Redacted ***");
        formatter.field("new_password", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
