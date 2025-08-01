// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a validation exception.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ValidationExceptionField {
    /// <p>The name of the exception.</p>
    pub name: ::std::string::String,
    /// <p>Describes the exception.</p>
    pub message: ::std::string::String,
}
impl ValidationExceptionField {
    /// <p>The name of the exception.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>Describes the exception.</p>
    pub fn message(&self) -> &str {
        use std::ops::Deref;
        self.message.deref()
    }
}
impl ValidationExceptionField {
    /// Creates a new builder-style object to manufacture [`ValidationExceptionField`](crate::types::ValidationExceptionField).
    pub fn builder() -> crate::types::builders::ValidationExceptionFieldBuilder {
        crate::types::builders::ValidationExceptionFieldBuilder::default()
    }
}

/// A builder for [`ValidationExceptionField`](crate::types::ValidationExceptionField).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ValidationExceptionFieldBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl ValidationExceptionFieldBuilder {
    /// <p>The name of the exception.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the exception.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the exception.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Describes the exception.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Describes the exception.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>Describes the exception.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`ValidationExceptionField`](crate::types::ValidationExceptionField).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::ValidationExceptionFieldBuilder::name)
    /// - [`message`](crate::types::builders::ValidationExceptionFieldBuilder::message)
    pub fn build(self) -> ::std::result::Result<crate::types::ValidationExceptionField, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ValidationExceptionField {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ValidationExceptionField",
                )
            })?,
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building ValidationExceptionField",
                )
            })?,
        })
    }
}
