// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `FailedItemErrorCode`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let faileditemerrorcode = unimplemented!();
/// match faileditemerrorcode {
///     FailedItemErrorCode::AccessDenied => { /* ... */ },
///     FailedItemErrorCode::DuplicateArn => { /* ... */ },
///     FailedItemErrorCode::InternalError => { /* ... */ },
///     FailedItemErrorCode::InvalidArn => { /* ... */ },
///     FailedItemErrorCode::ItemDoesNotExist => { /* ... */ },
///     FailedItemErrorCode::LimitExceeded => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `faileditemerrorcode` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `FailedItemErrorCode::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `FailedItemErrorCode::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `FailedItemErrorCode::NewFeature` is defined.
/// Specifically, when `faileditemerrorcode` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `FailedItemErrorCode::NewFeature` also yielding `"NewFeature"`.
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
pub enum FailedItemErrorCode {
    #[allow(missing_docs)] // documentation missing in model
    AccessDenied,
    #[allow(missing_docs)] // documentation missing in model
    DuplicateArn,
    #[allow(missing_docs)] // documentation missing in model
    InternalError,
    #[allow(missing_docs)] // documentation missing in model
    InvalidArn,
    #[allow(missing_docs)] // documentation missing in model
    ItemDoesNotExist,
    #[allow(missing_docs)] // documentation missing in model
    LimitExceeded,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for FailedItemErrorCode {
    fn from(s: &str) -> Self {
        match s {
            "ACCESS_DENIED" => FailedItemErrorCode::AccessDenied,
            "DUPLICATE_ARN" => FailedItemErrorCode::DuplicateArn,
            "INTERNAL_ERROR" => FailedItemErrorCode::InternalError,
            "INVALID_ARN" => FailedItemErrorCode::InvalidArn,
            "ITEM_DOES_NOT_EXIST" => FailedItemErrorCode::ItemDoesNotExist,
            "LIMIT_EXCEEDED" => FailedItemErrorCode::LimitExceeded,
            other => FailedItemErrorCode::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for FailedItemErrorCode {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(FailedItemErrorCode::from(s))
    }
}
impl FailedItemErrorCode {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            FailedItemErrorCode::AccessDenied => "ACCESS_DENIED",
            FailedItemErrorCode::DuplicateArn => "DUPLICATE_ARN",
            FailedItemErrorCode::InternalError => "INTERNAL_ERROR",
            FailedItemErrorCode::InvalidArn => "INVALID_ARN",
            FailedItemErrorCode::ItemDoesNotExist => "ITEM_DOES_NOT_EXIST",
            FailedItemErrorCode::LimitExceeded => "LIMIT_EXCEEDED",
            FailedItemErrorCode::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACCESS_DENIED",
            "DUPLICATE_ARN",
            "INTERNAL_ERROR",
            "INVALID_ARN",
            "ITEM_DOES_NOT_EXIST",
            "LIMIT_EXCEEDED",
        ]
    }
}
impl ::std::convert::AsRef<str> for FailedItemErrorCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl FailedItemErrorCode {
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
impl ::std::fmt::Display for FailedItemErrorCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            FailedItemErrorCode::AccessDenied => write!(f, "ACCESS_DENIED"),
            FailedItemErrorCode::DuplicateArn => write!(f, "DUPLICATE_ARN"),
            FailedItemErrorCode::InternalError => write!(f, "INTERNAL_ERROR"),
            FailedItemErrorCode::InvalidArn => write!(f, "INVALID_ARN"),
            FailedItemErrorCode::ItemDoesNotExist => write!(f, "ITEM_DOES_NOT_EXIST"),
            FailedItemErrorCode::LimitExceeded => write!(f, "LIMIT_EXCEEDED"),
            FailedItemErrorCode::Unknown(value) => write!(f, "{}", value),
        }
    }
}
