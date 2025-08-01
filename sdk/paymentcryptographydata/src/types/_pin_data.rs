// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Parameters that are required to generate, translate, or verify PIN data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub enum PinData {
    /// <p>The PIN offset value.</p>
    PinOffset(::std::string::String),
    /// <p>The unique data to identify a cardholder. In most cases, this is the same as cardholder's Primary Account Number (PAN). If a value is not provided, it defaults to PAN.</p>
    VerificationValue(::std::string::String),
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
impl PinData {
    /// Tries to convert the enum instance into [`PinOffset`](crate::types::PinData::PinOffset), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_pin_offset(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let PinData::PinOffset(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`PinOffset`](crate::types::PinData::PinOffset).
    pub fn is_pin_offset(&self) -> bool {
        self.as_pin_offset().is_ok()
    }
    /// Tries to convert the enum instance into [`VerificationValue`](crate::types::PinData::VerificationValue), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_verification_value(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let PinData::VerificationValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`VerificationValue`](crate::types::PinData::VerificationValue).
    pub fn is_verification_value(&self) -> bool {
        self.as_verification_value().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
impl ::std::fmt::Debug for PinData {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            PinData::PinOffset(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            PinData::VerificationValue(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            PinData::Unknown => f.debug_tuple("Unknown").finish(),
        }
    }
}
