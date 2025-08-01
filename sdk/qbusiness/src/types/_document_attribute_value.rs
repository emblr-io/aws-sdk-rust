// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The value of a document attribute. You can only provide one value for a document attribute.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum DocumentAttributeValue {
    /// <p>A date expressed as an ISO 8601 string.</p>
    /// <p>It's important for the time zone to be included in the ISO 8601 date-time format. For example, 2012-03-25T12:30:10+01:00 is the ISO 8601 date-time format for March 25th 2012 at 12:30PM (plus 10 seconds) in Central European Time.</p>
    DateValue(::aws_smithy_types::DateTime),
    /// <p>A long integer value.</p>
    LongValue(i64),
    /// <p>A list of strings.</p>
    StringListValue(::std::vec::Vec<::std::string::String>),
    /// <p>A string.</p>
    StringValue(::std::string::String),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl DocumentAttributeValue {
    /// Tries to convert the enum instance into [`DateValue`](crate::types::DocumentAttributeValue::DateValue), extracting the inner [`DateTime`](::aws_smithy_types::DateTime).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_date_value(&self) -> ::std::result::Result<&::aws_smithy_types::DateTime, &Self> {
        if let DocumentAttributeValue::DateValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DateValue`](crate::types::DocumentAttributeValue::DateValue).
    pub fn is_date_value(&self) -> bool {
        self.as_date_value().is_ok()
    }
    /// Tries to convert the enum instance into [`LongValue`](crate::types::DocumentAttributeValue::LongValue), extracting the inner [`i64`](i64).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_long_value(&self) -> ::std::result::Result<&i64, &Self> {
        if let DocumentAttributeValue::LongValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`LongValue`](crate::types::DocumentAttributeValue::LongValue).
    pub fn is_long_value(&self) -> bool {
        self.as_long_value().is_ok()
    }
    /// Tries to convert the enum instance into [`StringListValue`](crate::types::DocumentAttributeValue::StringListValue), extracting the inner [`Vec`](::std::vec::Vec).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_string_list_value(&self) -> ::std::result::Result<&::std::vec::Vec<::std::string::String>, &Self> {
        if let DocumentAttributeValue::StringListValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`StringListValue`](crate::types::DocumentAttributeValue::StringListValue).
    pub fn is_string_list_value(&self) -> bool {
        self.as_string_list_value().is_ok()
    }
    /// Tries to convert the enum instance into [`StringValue`](crate::types::DocumentAttributeValue::StringValue), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_string_value(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let DocumentAttributeValue::StringValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`StringValue`](crate::types::DocumentAttributeValue::StringValue).
    pub fn is_string_value(&self) -> bool {
        self.as_string_value().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
