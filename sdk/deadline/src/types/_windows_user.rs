// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Windows user details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WindowsUser {
    /// <p>The user.</p>
    pub user: ::std::string::String,
    /// <p>The password ARN for the Windows user.</p>
    pub password_arn: ::std::string::String,
}
impl WindowsUser {
    /// <p>The user.</p>
    pub fn user(&self) -> &str {
        use std::ops::Deref;
        self.user.deref()
    }
    /// <p>The password ARN for the Windows user.</p>
    pub fn password_arn(&self) -> &str {
        use std::ops::Deref;
        self.password_arn.deref()
    }
}
impl WindowsUser {
    /// Creates a new builder-style object to manufacture [`WindowsUser`](crate::types::WindowsUser).
    pub fn builder() -> crate::types::builders::WindowsUserBuilder {
        crate::types::builders::WindowsUserBuilder::default()
    }
}

/// A builder for [`WindowsUser`](crate::types::WindowsUser).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WindowsUserBuilder {
    pub(crate) user: ::std::option::Option<::std::string::String>,
    pub(crate) password_arn: ::std::option::Option<::std::string::String>,
}
impl WindowsUserBuilder {
    /// <p>The user.</p>
    /// This field is required.
    pub fn user(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user.</p>
    pub fn set_user(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user = input;
        self
    }
    /// <p>The user.</p>
    pub fn get_user(&self) -> &::std::option::Option<::std::string::String> {
        &self.user
    }
    /// <p>The password ARN for the Windows user.</p>
    /// This field is required.
    pub fn password_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The password ARN for the Windows user.</p>
    pub fn set_password_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password_arn = input;
        self
    }
    /// <p>The password ARN for the Windows user.</p>
    pub fn get_password_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.password_arn
    }
    /// Consumes the builder and constructs a [`WindowsUser`](crate::types::WindowsUser).
    /// This method will fail if any of the following fields are not set:
    /// - [`user`](crate::types::builders::WindowsUserBuilder::user)
    /// - [`password_arn`](crate::types::builders::WindowsUserBuilder::password_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::WindowsUser, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::WindowsUser {
            user: self.user.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "user",
                    "user was not specified but it is required when building WindowsUser",
                )
            })?,
            password_arn: self.password_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "password_arn",
                    "password_arn was not specified but it is required when building WindowsUser",
                )
            })?,
        })
    }
}
