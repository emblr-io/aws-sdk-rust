// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about answer data for a contact evaluation. Answer data must be either string, numeric, or not applicable.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum EvaluationAnswerData {
    /// <p>The flag to mark the question as not applicable.</p>
    NotApplicable(bool),
    /// <p>The numeric value for an answer in a contact evaluation.</p>
    NumericValue(f64),
    /// <p>The string value for an answer in a contact evaluation.</p>
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
impl EvaluationAnswerData {
    /// Tries to convert the enum instance into [`NotApplicable`](crate::types::EvaluationAnswerData::NotApplicable), extracting the inner [`bool`](bool).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_not_applicable(&self) -> ::std::result::Result<&bool, &Self> {
        if let EvaluationAnswerData::NotApplicable(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`NotApplicable`](crate::types::EvaluationAnswerData::NotApplicable).
    pub fn is_not_applicable(&self) -> bool {
        self.as_not_applicable().is_ok()
    }
    /// Tries to convert the enum instance into [`NumericValue`](crate::types::EvaluationAnswerData::NumericValue), extracting the inner [`f64`](f64).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_numeric_value(&self) -> ::std::result::Result<&f64, &Self> {
        if let EvaluationAnswerData::NumericValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`NumericValue`](crate::types::EvaluationAnswerData::NumericValue).
    pub fn is_numeric_value(&self) -> bool {
        self.as_numeric_value().is_ok()
    }
    /// Tries to convert the enum instance into [`StringValue`](crate::types::EvaluationAnswerData::StringValue), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_string_value(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let EvaluationAnswerData::StringValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`StringValue`](crate::types::EvaluationAnswerData::StringValue).
    pub fn is_string_value(&self) -> bool {
        self.as_string_value().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
