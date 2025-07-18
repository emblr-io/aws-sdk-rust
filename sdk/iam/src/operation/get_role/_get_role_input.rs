// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRoleInput {
    /// <p>The name of the IAM role to get information about.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub role_name: ::std::option::Option<::std::string::String>,
}
impl GetRoleInput {
    /// <p>The name of the IAM role to get information about.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn role_name(&self) -> ::std::option::Option<&str> {
        self.role_name.as_deref()
    }
}
impl GetRoleInput {
    /// Creates a new builder-style object to manufacture [`GetRoleInput`](crate::operation::get_role::GetRoleInput).
    pub fn builder() -> crate::operation::get_role::builders::GetRoleInputBuilder {
        crate::operation::get_role::builders::GetRoleInputBuilder::default()
    }
}

/// A builder for [`GetRoleInput`](crate::operation::get_role::GetRoleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRoleInputBuilder {
    pub(crate) role_name: ::std::option::Option<::std::string::String>,
}
impl GetRoleInputBuilder {
    /// <p>The name of the IAM role to get information about.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    /// This field is required.
    pub fn role_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the IAM role to get information about.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn set_role_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_name = input;
        self
    }
    /// <p>The name of the IAM role to get information about.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn get_role_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_name
    }
    /// Consumes the builder and constructs a [`GetRoleInput`](crate::operation::get_role::GetRoleInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_role::GetRoleInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_role::GetRoleInput { role_name: self.role_name })
    }
}
