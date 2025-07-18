// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateLoginProfileInput {
    /// <p>The name of the user whose password you want to update.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub user_name: ::std::option::Option<::std::string::String>,
    /// <p>The new password for the specified IAM user.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    /// <p>However, the format can be further restricted by the account administrator by setting a password policy on the Amazon Web Services account. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccountPasswordPolicy.html">UpdateAccountPasswordPolicy</a>.</p>
    pub password: ::std::option::Option<::std::string::String>,
    /// <p>Allows this new password to be used only once by requiring the specified IAM user to set a new password on next sign-in.</p>
    pub password_reset_required: ::std::option::Option<bool>,
}
impl UpdateLoginProfileInput {
    /// <p>The name of the user whose password you want to update.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn user_name(&self) -> ::std::option::Option<&str> {
        self.user_name.as_deref()
    }
    /// <p>The new password for the specified IAM user.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    /// <p>However, the format can be further restricted by the account administrator by setting a password policy on the Amazon Web Services account. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccountPasswordPolicy.html">UpdateAccountPasswordPolicy</a>.</p>
    pub fn password(&self) -> ::std::option::Option<&str> {
        self.password.as_deref()
    }
    /// <p>Allows this new password to be used only once by requiring the specified IAM user to set a new password on next sign-in.</p>
    pub fn password_reset_required(&self) -> ::std::option::Option<bool> {
        self.password_reset_required
    }
}
impl ::std::fmt::Debug for UpdateLoginProfileInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateLoginProfileInput");
        formatter.field("user_name", &self.user_name);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("password_reset_required", &self.password_reset_required);
        formatter.finish()
    }
}
impl UpdateLoginProfileInput {
    /// Creates a new builder-style object to manufacture [`UpdateLoginProfileInput`](crate::operation::update_login_profile::UpdateLoginProfileInput).
    pub fn builder() -> crate::operation::update_login_profile::builders::UpdateLoginProfileInputBuilder {
        crate::operation::update_login_profile::builders::UpdateLoginProfileInputBuilder::default()
    }
}

/// A builder for [`UpdateLoginProfileInput`](crate::operation::update_login_profile::UpdateLoginProfileInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateLoginProfileInputBuilder {
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
    pub(crate) password: ::std::option::Option<::std::string::String>,
    pub(crate) password_reset_required: ::std::option::Option<bool>,
}
impl UpdateLoginProfileInputBuilder {
    /// <p>The name of the user whose password you want to update.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    /// This field is required.
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the user whose password you want to update.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>The name of the user whose password you want to update.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    /// <p>The new password for the specified IAM user.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    /// <p>However, the format can be further restricted by the account administrator by setting a password policy on the Amazon Web Services account. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccountPasswordPolicy.html">UpdateAccountPasswordPolicy</a>.</p>
    pub fn password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new password for the specified IAM user.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    /// <p>However, the format can be further restricted by the account administrator by setting a password policy on the Amazon Web Services account. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccountPasswordPolicy.html">UpdateAccountPasswordPolicy</a>.</p>
    pub fn set_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password = input;
        self
    }
    /// <p>The new password for the specified IAM user.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    /// <p>However, the format can be further restricted by the account administrator by setting a password policy on the Amazon Web Services account. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccountPasswordPolicy.html">UpdateAccountPasswordPolicy</a>.</p>
    pub fn get_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.password
    }
    /// <p>Allows this new password to be used only once by requiring the specified IAM user to set a new password on next sign-in.</p>
    pub fn password_reset_required(mut self, input: bool) -> Self {
        self.password_reset_required = ::std::option::Option::Some(input);
        self
    }
    /// <p>Allows this new password to be used only once by requiring the specified IAM user to set a new password on next sign-in.</p>
    pub fn set_password_reset_required(mut self, input: ::std::option::Option<bool>) -> Self {
        self.password_reset_required = input;
        self
    }
    /// <p>Allows this new password to be used only once by requiring the specified IAM user to set a new password on next sign-in.</p>
    pub fn get_password_reset_required(&self) -> &::std::option::Option<bool> {
        &self.password_reset_required
    }
    /// Consumes the builder and constructs a [`UpdateLoginProfileInput`](crate::operation::update_login_profile::UpdateLoginProfileInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_login_profile::UpdateLoginProfileInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_login_profile::UpdateLoginProfileInput {
            user_name: self.user_name,
            password: self.password,
            password_reset_required: self.password_reset_required,
        })
    }
}
impl ::std::fmt::Debug for UpdateLoginProfileInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateLoginProfileInputBuilder");
        formatter.field("user_name", &self.user_name);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("password_reset_required", &self.password_reset_required);
        formatter.finish()
    }
}
