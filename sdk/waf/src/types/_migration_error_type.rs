// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `MigrationErrorType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let migrationerrortype = unimplemented!();
/// match migrationerrortype {
///     MigrationErrorType::EntityNotFound => { /* ... */ },
///     MigrationErrorType::EntityNotSupported => { /* ... */ },
///     MigrationErrorType::S3BucketInvalidRegion => { /* ... */ },
///     MigrationErrorType::S3BucketNotAccessible => { /* ... */ },
///     MigrationErrorType::S3BucketNotFound => { /* ... */ },
///     MigrationErrorType::S3BucketNoPermission => { /* ... */ },
///     MigrationErrorType::S3InternalError => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `migrationerrortype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `MigrationErrorType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `MigrationErrorType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `MigrationErrorType::NewFeature` is defined.
/// Specifically, when `migrationerrortype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `MigrationErrorType::NewFeature` also yielding `"NewFeature"`.
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
pub enum MigrationErrorType {
    #[allow(missing_docs)] // documentation missing in model
    EntityNotFound,
    #[allow(missing_docs)] // documentation missing in model
    EntityNotSupported,
    #[allow(missing_docs)] // documentation missing in model
    S3BucketInvalidRegion,
    #[allow(missing_docs)] // documentation missing in model
    S3BucketNotAccessible,
    #[allow(missing_docs)] // documentation missing in model
    S3BucketNotFound,
    #[allow(missing_docs)] // documentation missing in model
    S3BucketNoPermission,
    #[allow(missing_docs)] // documentation missing in model
    S3InternalError,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for MigrationErrorType {
    fn from(s: &str) -> Self {
        match s {
            "ENTITY_NOT_FOUND" => MigrationErrorType::EntityNotFound,
            "ENTITY_NOT_SUPPORTED" => MigrationErrorType::EntityNotSupported,
            "S3_BUCKET_INVALID_REGION" => MigrationErrorType::S3BucketInvalidRegion,
            "S3_BUCKET_NOT_ACCESSIBLE" => MigrationErrorType::S3BucketNotAccessible,
            "S3_BUCKET_NOT_FOUND" => MigrationErrorType::S3BucketNotFound,
            "S3_BUCKET_NO_PERMISSION" => MigrationErrorType::S3BucketNoPermission,
            "S3_INTERNAL_ERROR" => MigrationErrorType::S3InternalError,
            other => MigrationErrorType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for MigrationErrorType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(MigrationErrorType::from(s))
    }
}
impl MigrationErrorType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            MigrationErrorType::EntityNotFound => "ENTITY_NOT_FOUND",
            MigrationErrorType::EntityNotSupported => "ENTITY_NOT_SUPPORTED",
            MigrationErrorType::S3BucketInvalidRegion => "S3_BUCKET_INVALID_REGION",
            MigrationErrorType::S3BucketNotAccessible => "S3_BUCKET_NOT_ACCESSIBLE",
            MigrationErrorType::S3BucketNotFound => "S3_BUCKET_NOT_FOUND",
            MigrationErrorType::S3BucketNoPermission => "S3_BUCKET_NO_PERMISSION",
            MigrationErrorType::S3InternalError => "S3_INTERNAL_ERROR",
            MigrationErrorType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ENTITY_NOT_FOUND",
            "ENTITY_NOT_SUPPORTED",
            "S3_BUCKET_INVALID_REGION",
            "S3_BUCKET_NOT_ACCESSIBLE",
            "S3_BUCKET_NOT_FOUND",
            "S3_BUCKET_NO_PERMISSION",
            "S3_INTERNAL_ERROR",
        ]
    }
}
impl ::std::convert::AsRef<str> for MigrationErrorType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl MigrationErrorType {
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
impl ::std::fmt::Display for MigrationErrorType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            MigrationErrorType::EntityNotFound => write!(f, "ENTITY_NOT_FOUND"),
            MigrationErrorType::EntityNotSupported => write!(f, "ENTITY_NOT_SUPPORTED"),
            MigrationErrorType::S3BucketInvalidRegion => write!(f, "S3_BUCKET_INVALID_REGION"),
            MigrationErrorType::S3BucketNotAccessible => write!(f, "S3_BUCKET_NOT_ACCESSIBLE"),
            MigrationErrorType::S3BucketNotFound => write!(f, "S3_BUCKET_NOT_FOUND"),
            MigrationErrorType::S3BucketNoPermission => write!(f, "S3_BUCKET_NO_PERMISSION"),
            MigrationErrorType::S3InternalError => write!(f, "S3_INTERNAL_ERROR"),
            MigrationErrorType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
