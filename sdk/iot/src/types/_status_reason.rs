// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provide additional context about the status of a command execution using a reason code and description.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StatusReason {
    /// <p>A code that provides additional context for the command execution status.</p>
    pub reason_code: ::std::string::String,
    /// <p>A literal string for devices to optionally provide additional information about the reason code for a command execution status.</p>
    pub reason_description: ::std::option::Option<::std::string::String>,
}
impl StatusReason {
    /// <p>A code that provides additional context for the command execution status.</p>
    pub fn reason_code(&self) -> &str {
        use std::ops::Deref;
        self.reason_code.deref()
    }
    /// <p>A literal string for devices to optionally provide additional information about the reason code for a command execution status.</p>
    pub fn reason_description(&self) -> ::std::option::Option<&str> {
        self.reason_description.as_deref()
    }
}
impl StatusReason {
    /// Creates a new builder-style object to manufacture [`StatusReason`](crate::types::StatusReason).
    pub fn builder() -> crate::types::builders::StatusReasonBuilder {
        crate::types::builders::StatusReasonBuilder::default()
    }
}

/// A builder for [`StatusReason`](crate::types::StatusReason).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StatusReasonBuilder {
    pub(crate) reason_code: ::std::option::Option<::std::string::String>,
    pub(crate) reason_description: ::std::option::Option<::std::string::String>,
}
impl StatusReasonBuilder {
    /// <p>A code that provides additional context for the command execution status.</p>
    /// This field is required.
    pub fn reason_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A code that provides additional context for the command execution status.</p>
    pub fn set_reason_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason_code = input;
        self
    }
    /// <p>A code that provides additional context for the command execution status.</p>
    pub fn get_reason_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason_code
    }
    /// <p>A literal string for devices to optionally provide additional information about the reason code for a command execution status.</p>
    pub fn reason_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A literal string for devices to optionally provide additional information about the reason code for a command execution status.</p>
    pub fn set_reason_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason_description = input;
        self
    }
    /// <p>A literal string for devices to optionally provide additional information about the reason code for a command execution status.</p>
    pub fn get_reason_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason_description
    }
    /// Consumes the builder and constructs a [`StatusReason`](crate::types::StatusReason).
    /// This method will fail if any of the following fields are not set:
    /// - [`reason_code`](crate::types::builders::StatusReasonBuilder::reason_code)
    pub fn build(self) -> ::std::result::Result<crate::types::StatusReason, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StatusReason {
            reason_code: self.reason_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "reason_code",
                    "reason_code was not specified but it is required when building StatusReason",
                )
            })?,
            reason_description: self.reason_description,
        })
    }
}
