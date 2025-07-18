// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that described the state of Amazon Inspector scans for an account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct State {
    /// <p>The status of Amazon Inspector for the account.</p>
    pub status: crate::types::Status,
    /// <p>The error code explaining why the account failed to enable Amazon Inspector.</p>
    pub error_code: crate::types::ErrorCode,
    /// <p>The error message received when the account failed to enable Amazon Inspector.</p>
    pub error_message: ::std::string::String,
}
impl State {
    /// <p>The status of Amazon Inspector for the account.</p>
    pub fn status(&self) -> &crate::types::Status {
        &self.status
    }
    /// <p>The error code explaining why the account failed to enable Amazon Inspector.</p>
    pub fn error_code(&self) -> &crate::types::ErrorCode {
        &self.error_code
    }
    /// <p>The error message received when the account failed to enable Amazon Inspector.</p>
    pub fn error_message(&self) -> &str {
        use std::ops::Deref;
        self.error_message.deref()
    }
}
impl State {
    /// Creates a new builder-style object to manufacture [`State`](crate::types::State).
    pub fn builder() -> crate::types::builders::StateBuilder {
        crate::types::builders::StateBuilder::default()
    }
}

/// A builder for [`State`](crate::types::State).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StateBuilder {
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    pub(crate) error_code: ::std::option::Option<crate::types::ErrorCode>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
}
impl StateBuilder {
    /// <p>The status of Amazon Inspector for the account.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of Amazon Inspector for the account.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of Amazon Inspector for the account.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
    }
    /// <p>The error code explaining why the account failed to enable Amazon Inspector.</p>
    /// This field is required.
    pub fn error_code(mut self, input: crate::types::ErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The error code explaining why the account failed to enable Amazon Inspector.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::ErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The error code explaining why the account failed to enable Amazon Inspector.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::ErrorCode> {
        &self.error_code
    }
    /// <p>The error message received when the account failed to enable Amazon Inspector.</p>
    /// This field is required.
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message received when the account failed to enable Amazon Inspector.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The error message received when the account failed to enable Amazon Inspector.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Consumes the builder and constructs a [`State`](crate::types::State).
    /// This method will fail if any of the following fields are not set:
    /// - [`status`](crate::types::builders::StateBuilder::status)
    /// - [`error_code`](crate::types::builders::StateBuilder::error_code)
    /// - [`error_message`](crate::types::builders::StateBuilder::error_message)
    pub fn build(self) -> ::std::result::Result<crate::types::State, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::State {
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building State",
                )
            })?,
            error_code: self.error_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "error_code",
                    "error_code was not specified but it is required when building State",
                )
            })?,
            error_message: self.error_message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "error_message",
                    "error_message was not specified but it is required when building State",
                )
            })?,
        })
    }
}
