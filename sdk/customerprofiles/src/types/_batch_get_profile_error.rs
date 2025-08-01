// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Error object describing why a specific profile failed.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetProfileError {
    /// <p>Status code for why a specific profile failed.</p>
    pub code: ::std::string::String,
    /// <p>Message describing why a specific profile failed.</p>
    pub message: ::std::string::String,
    /// <p>The profile id that failed.</p>
    pub profile_id: ::std::string::String,
}
impl BatchGetProfileError {
    /// <p>Status code for why a specific profile failed.</p>
    pub fn code(&self) -> &str {
        use std::ops::Deref;
        self.code.deref()
    }
    /// <p>Message describing why a specific profile failed.</p>
    pub fn message(&self) -> &str {
        use std::ops::Deref;
        self.message.deref()
    }
    /// <p>The profile id that failed.</p>
    pub fn profile_id(&self) -> &str {
        use std::ops::Deref;
        self.profile_id.deref()
    }
}
impl BatchGetProfileError {
    /// Creates a new builder-style object to manufacture [`BatchGetProfileError`](crate::types::BatchGetProfileError).
    pub fn builder() -> crate::types::builders::BatchGetProfileErrorBuilder {
        crate::types::builders::BatchGetProfileErrorBuilder::default()
    }
}

/// A builder for [`BatchGetProfileError`](crate::types::BatchGetProfileError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetProfileErrorBuilder {
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) profile_id: ::std::option::Option<::std::string::String>,
}
impl BatchGetProfileErrorBuilder {
    /// <p>Status code for why a specific profile failed.</p>
    /// This field is required.
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Status code for why a specific profile failed.</p>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>Status code for why a specific profile failed.</p>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// <p>Message describing why a specific profile failed.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Message describing why a specific profile failed.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>Message describing why a specific profile failed.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>The profile id that failed.</p>
    /// This field is required.
    pub fn profile_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The profile id that failed.</p>
    pub fn set_profile_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_id = input;
        self
    }
    /// <p>The profile id that failed.</p>
    pub fn get_profile_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_id
    }
    /// Consumes the builder and constructs a [`BatchGetProfileError`](crate::types::BatchGetProfileError).
    /// This method will fail if any of the following fields are not set:
    /// - [`code`](crate::types::builders::BatchGetProfileErrorBuilder::code)
    /// - [`message`](crate::types::builders::BatchGetProfileErrorBuilder::message)
    /// - [`profile_id`](crate::types::builders::BatchGetProfileErrorBuilder::profile_id)
    pub fn build(self) -> ::std::result::Result<crate::types::BatchGetProfileError, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchGetProfileError {
            code: self.code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "code",
                    "code was not specified but it is required when building BatchGetProfileError",
                )
            })?,
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building BatchGetProfileError",
                )
            })?,
            profile_id: self.profile_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "profile_id",
                    "profile_id was not specified but it is required when building BatchGetProfileError",
                )
            })?,
        })
    }
}
