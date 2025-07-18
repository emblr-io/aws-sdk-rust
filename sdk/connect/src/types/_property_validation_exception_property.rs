// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about why a property is not valid.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PropertyValidationExceptionProperty {
    /// <p>The full property path.</p>
    pub property_path: ::std::string::String,
    /// <p>Why the property is not valid.</p>
    pub reason: crate::types::PropertyValidationExceptionReason,
    /// <p>A message describing why the property is not valid.</p>
    pub message: ::std::string::String,
}
impl PropertyValidationExceptionProperty {
    /// <p>The full property path.</p>
    pub fn property_path(&self) -> &str {
        use std::ops::Deref;
        self.property_path.deref()
    }
    /// <p>Why the property is not valid.</p>
    pub fn reason(&self) -> &crate::types::PropertyValidationExceptionReason {
        &self.reason
    }
    /// <p>A message describing why the property is not valid.</p>
    pub fn message(&self) -> &str {
        use std::ops::Deref;
        self.message.deref()
    }
}
impl PropertyValidationExceptionProperty {
    /// Creates a new builder-style object to manufacture [`PropertyValidationExceptionProperty`](crate::types::PropertyValidationExceptionProperty).
    pub fn builder() -> crate::types::builders::PropertyValidationExceptionPropertyBuilder {
        crate::types::builders::PropertyValidationExceptionPropertyBuilder::default()
    }
}

/// A builder for [`PropertyValidationExceptionProperty`](crate::types::PropertyValidationExceptionProperty).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PropertyValidationExceptionPropertyBuilder {
    pub(crate) property_path: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<crate::types::PropertyValidationExceptionReason>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl PropertyValidationExceptionPropertyBuilder {
    /// <p>The full property path.</p>
    /// This field is required.
    pub fn property_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.property_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The full property path.</p>
    pub fn set_property_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.property_path = input;
        self
    }
    /// <p>The full property path.</p>
    pub fn get_property_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.property_path
    }
    /// <p>Why the property is not valid.</p>
    /// This field is required.
    pub fn reason(mut self, input: crate::types::PropertyValidationExceptionReason) -> Self {
        self.reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>Why the property is not valid.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<crate::types::PropertyValidationExceptionReason>) -> Self {
        self.reason = input;
        self
    }
    /// <p>Why the property is not valid.</p>
    pub fn get_reason(&self) -> &::std::option::Option<crate::types::PropertyValidationExceptionReason> {
        &self.reason
    }
    /// <p>A message describing why the property is not valid.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message describing why the property is not valid.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message describing why the property is not valid.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`PropertyValidationExceptionProperty`](crate::types::PropertyValidationExceptionProperty).
    /// This method will fail if any of the following fields are not set:
    /// - [`property_path`](crate::types::builders::PropertyValidationExceptionPropertyBuilder::property_path)
    /// - [`reason`](crate::types::builders::PropertyValidationExceptionPropertyBuilder::reason)
    /// - [`message`](crate::types::builders::PropertyValidationExceptionPropertyBuilder::message)
    pub fn build(self) -> ::std::result::Result<crate::types::PropertyValidationExceptionProperty, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PropertyValidationExceptionProperty {
            property_path: self.property_path.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "property_path",
                    "property_path was not specified but it is required when building PropertyValidationExceptionProperty",
                )
            })?,
            reason: self.reason.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "reason",
                    "reason was not specified but it is required when building PropertyValidationExceptionProperty",
                )
            })?,
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building PropertyValidationExceptionProperty",
                )
            })?,
        })
    }
}
