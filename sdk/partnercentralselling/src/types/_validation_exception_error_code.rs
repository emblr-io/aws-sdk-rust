// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ValidationExceptionErrorCode`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let validationexceptionerrorcode = unimplemented!();
/// match validationexceptionerrorcode {
///     ValidationExceptionErrorCode::ActionNotPermitted => { /* ... */ },
///     ValidationExceptionErrorCode::DuplicateKeyValue => { /* ... */ },
///     ValidationExceptionErrorCode::InvalidEnumValue => { /* ... */ },
///     ValidationExceptionErrorCode::InvalidResourceState => { /* ... */ },
///     ValidationExceptionErrorCode::InvalidStringFormat => { /* ... */ },
///     ValidationExceptionErrorCode::InvalidValue => { /* ... */ },
///     ValidationExceptionErrorCode::RequiredFieldMissing => { /* ... */ },
///     ValidationExceptionErrorCode::TooManyValues => { /* ... */ },
///     ValidationExceptionErrorCode::ValueOutOfRange => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `validationexceptionerrorcode` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ValidationExceptionErrorCode::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ValidationExceptionErrorCode::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ValidationExceptionErrorCode::NewFeature` is defined.
/// Specifically, when `validationexceptionerrorcode` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ValidationExceptionErrorCode::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum ValidationExceptionErrorCode {
    #[allow(missing_docs)] // documentation missing in model
    ActionNotPermitted,
    #[allow(missing_docs)] // documentation missing in model
    DuplicateKeyValue,
    #[allow(missing_docs)] // documentation missing in model
    InvalidEnumValue,
    #[allow(missing_docs)] // documentation missing in model
    InvalidResourceState,
    #[allow(missing_docs)] // documentation missing in model
    InvalidStringFormat,
    #[allow(missing_docs)] // documentation missing in model
    InvalidValue,
    #[allow(missing_docs)] // documentation missing in model
    RequiredFieldMissing,
    #[allow(missing_docs)] // documentation missing in model
    TooManyValues,
    #[allow(missing_docs)] // documentation missing in model
    ValueOutOfRange,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ValidationExceptionErrorCode {
    fn from(s: &str) -> Self {
        match s {
            "ACTION_NOT_PERMITTED" => ValidationExceptionErrorCode::ActionNotPermitted,
            "DUPLICATE_KEY_VALUE" => ValidationExceptionErrorCode::DuplicateKeyValue,
            "INVALID_ENUM_VALUE" => ValidationExceptionErrorCode::InvalidEnumValue,
            "INVALID_RESOURCE_STATE" => ValidationExceptionErrorCode::InvalidResourceState,
            "INVALID_STRING_FORMAT" => ValidationExceptionErrorCode::InvalidStringFormat,
            "INVALID_VALUE" => ValidationExceptionErrorCode::InvalidValue,
            "REQUIRED_FIELD_MISSING" => ValidationExceptionErrorCode::RequiredFieldMissing,
            "TOO_MANY_VALUES" => ValidationExceptionErrorCode::TooManyValues,
            "VALUE_OUT_OF_RANGE" => ValidationExceptionErrorCode::ValueOutOfRange,
            other => ValidationExceptionErrorCode::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ValidationExceptionErrorCode {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ValidationExceptionErrorCode::from(s))
    }
}
impl ValidationExceptionErrorCode {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ValidationExceptionErrorCode::ActionNotPermitted => "ACTION_NOT_PERMITTED",
            ValidationExceptionErrorCode::DuplicateKeyValue => "DUPLICATE_KEY_VALUE",
            ValidationExceptionErrorCode::InvalidEnumValue => "INVALID_ENUM_VALUE",
            ValidationExceptionErrorCode::InvalidResourceState => "INVALID_RESOURCE_STATE",
            ValidationExceptionErrorCode::InvalidStringFormat => "INVALID_STRING_FORMAT",
            ValidationExceptionErrorCode::InvalidValue => "INVALID_VALUE",
            ValidationExceptionErrorCode::RequiredFieldMissing => "REQUIRED_FIELD_MISSING",
            ValidationExceptionErrorCode::TooManyValues => "TOO_MANY_VALUES",
            ValidationExceptionErrorCode::ValueOutOfRange => "VALUE_OUT_OF_RANGE",
            ValidationExceptionErrorCode::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACTION_NOT_PERMITTED",
            "DUPLICATE_KEY_VALUE",
            "INVALID_ENUM_VALUE",
            "INVALID_RESOURCE_STATE",
            "INVALID_STRING_FORMAT",
            "INVALID_VALUE",
            "REQUIRED_FIELD_MISSING",
            "TOO_MANY_VALUES",
            "VALUE_OUT_OF_RANGE",
        ]
    }
}
impl ::std::convert::AsRef<str> for ValidationExceptionErrorCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ValidationExceptionErrorCode {
    /// Parses the enum value while disallowing unknown variants.
    ///
    /// Unknown variants will result in an error.
    pub fn try_parse(value: &str) -> ::std::result::Result<Self, crate::error::UnknownVariantError> {
        match Self::from(value) {
            #[allow(deprecated)]
            Self::Unknown(_) => ::std::result::Result::Err(crate::error::UnknownVariantError::new(value)),
            known => Ok(known),
        }
    }
}
impl ::std::fmt::Display for ValidationExceptionErrorCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ValidationExceptionErrorCode::ActionNotPermitted => write!(f, "ACTION_NOT_PERMITTED"),
            ValidationExceptionErrorCode::DuplicateKeyValue => write!(f, "DUPLICATE_KEY_VALUE"),
            ValidationExceptionErrorCode::InvalidEnumValue => write!(f, "INVALID_ENUM_VALUE"),
            ValidationExceptionErrorCode::InvalidResourceState => write!(f, "INVALID_RESOURCE_STATE"),
            ValidationExceptionErrorCode::InvalidStringFormat => write!(f, "INVALID_STRING_FORMAT"),
            ValidationExceptionErrorCode::InvalidValue => write!(f, "INVALID_VALUE"),
            ValidationExceptionErrorCode::RequiredFieldMissing => write!(f, "REQUIRED_FIELD_MISSING"),
            ValidationExceptionErrorCode::TooManyValues => write!(f, "TOO_MANY_VALUES"),
            ValidationExceptionErrorCode::ValueOutOfRange => write!(f, "VALUE_OUT_OF_RANGE"),
            ValidationExceptionErrorCode::Unknown(value) => write!(f, "{}", value),
        }
    }
}
