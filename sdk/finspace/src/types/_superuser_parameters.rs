// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration information for the superuser.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SuperuserParameters {
    /// <p>The email address of the superuser.</p>
    pub email_address: ::std::string::String,
    /// <p>The first name of the superuser.</p>
    pub first_name: ::std::string::String,
    /// <p>The last name of the superuser.</p>
    pub last_name: ::std::string::String,
}
impl SuperuserParameters {
    /// <p>The email address of the superuser.</p>
    pub fn email_address(&self) -> &str {
        use std::ops::Deref;
        self.email_address.deref()
    }
    /// <p>The first name of the superuser.</p>
    pub fn first_name(&self) -> &str {
        use std::ops::Deref;
        self.first_name.deref()
    }
    /// <p>The last name of the superuser.</p>
    pub fn last_name(&self) -> &str {
        use std::ops::Deref;
        self.last_name.deref()
    }
}
impl ::std::fmt::Debug for SuperuserParameters {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SuperuserParameters");
        formatter.field("email_address", &"*** Sensitive Data Redacted ***");
        formatter.field("first_name", &self.first_name);
        formatter.field("last_name", &self.last_name);
        formatter.finish()
    }
}
impl SuperuserParameters {
    /// Creates a new builder-style object to manufacture [`SuperuserParameters`](crate::types::SuperuserParameters).
    pub fn builder() -> crate::types::builders::SuperuserParametersBuilder {
        crate::types::builders::SuperuserParametersBuilder::default()
    }
}

/// A builder for [`SuperuserParameters`](crate::types::SuperuserParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SuperuserParametersBuilder {
    pub(crate) email_address: ::std::option::Option<::std::string::String>,
    pub(crate) first_name: ::std::option::Option<::std::string::String>,
    pub(crate) last_name: ::std::option::Option<::std::string::String>,
}
impl SuperuserParametersBuilder {
    /// <p>The email address of the superuser.</p>
    /// This field is required.
    pub fn email_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email address of the superuser.</p>
    pub fn set_email_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_address = input;
        self
    }
    /// <p>The email address of the superuser.</p>
    pub fn get_email_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_address
    }
    /// <p>The first name of the superuser.</p>
    /// This field is required.
    pub fn first_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.first_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The first name of the superuser.</p>
    pub fn set_first_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.first_name = input;
        self
    }
    /// <p>The first name of the superuser.</p>
    pub fn get_first_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.first_name
    }
    /// <p>The last name of the superuser.</p>
    /// This field is required.
    pub fn last_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The last name of the superuser.</p>
    pub fn set_last_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_name = input;
        self
    }
    /// <p>The last name of the superuser.</p>
    pub fn get_last_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_name
    }
    /// Consumes the builder and constructs a [`SuperuserParameters`](crate::types::SuperuserParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`email_address`](crate::types::builders::SuperuserParametersBuilder::email_address)
    /// - [`first_name`](crate::types::builders::SuperuserParametersBuilder::first_name)
    /// - [`last_name`](crate::types::builders::SuperuserParametersBuilder::last_name)
    pub fn build(self) -> ::std::result::Result<crate::types::SuperuserParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SuperuserParameters {
            email_address: self.email_address.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "email_address",
                    "email_address was not specified but it is required when building SuperuserParameters",
                )
            })?,
            first_name: self.first_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "first_name",
                    "first_name was not specified but it is required when building SuperuserParameters",
                )
            })?,
            last_name: self.last_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_name",
                    "last_name was not specified but it is required when building SuperuserParameters",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for SuperuserParametersBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SuperuserParametersBuilder");
        formatter.field("email_address", &"*** Sensitive Data Redacted ***");
        formatter.field("first_name", &self.first_name);
        formatter.field("last_name", &self.last_name);
        formatter.finish()
    }
}
