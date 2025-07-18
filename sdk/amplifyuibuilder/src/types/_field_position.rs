// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the field position.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum FieldPosition {
    /// <p>The field position is below the field specified by the string.</p>
    Below(::std::string::String),
    /// <p>The field position is fixed and doesn't change in relation to other fields.</p>
    Fixed(crate::types::FixedPosition),
    /// <p>The field position is to the right of the field specified by the string.</p>
    RightOf(::std::string::String),
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
impl FieldPosition {
    /// Tries to convert the enum instance into [`Below`](crate::types::FieldPosition::Below), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_below(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let FieldPosition::Below(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Below`](crate::types::FieldPosition::Below).
    pub fn is_below(&self) -> bool {
        self.as_below().is_ok()
    }
    /// Tries to convert the enum instance into [`Fixed`](crate::types::FieldPosition::Fixed), extracting the inner [`FixedPosition`](crate::types::FixedPosition).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_fixed(&self) -> ::std::result::Result<&crate::types::FixedPosition, &Self> {
        if let FieldPosition::Fixed(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Fixed`](crate::types::FieldPosition::Fixed).
    pub fn is_fixed(&self) -> bool {
        self.as_fixed().is_ok()
    }
    /// Tries to convert the enum instance into [`RightOf`](crate::types::FieldPosition::RightOf), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_right_of(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let FieldPosition::RightOf(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`RightOf`](crate::types::FieldPosition::RightOf).
    pub fn is_right_of(&self) -> bool {
        self.as_right_of().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
