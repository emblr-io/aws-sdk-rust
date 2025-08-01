// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `UserStatusType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let userstatustype = unimplemented!();
/// match userstatustype {
///     UserStatusType::Archived => { /* ... */ },
///     UserStatusType::Compromised => { /* ... */ },
///     UserStatusType::Confirmed => { /* ... */ },
///     UserStatusType::ExternalProvider => { /* ... */ },
///     UserStatusType::ForceChangePassword => { /* ... */ },
///     UserStatusType::ResetRequired => { /* ... */ },
///     UserStatusType::Unconfirmed => { /* ... */ },
///     UserStatusType::UnknownValue => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `userstatustype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `UserStatusType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `UserStatusType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `UserStatusType::NewFeature` is defined.
/// Specifically, when `userstatustype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `UserStatusType::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
///
/// _Note: `UserStatusType::Unknown` has been renamed to `::UnknownValue`._
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum UserStatusType {
    #[allow(missing_docs)] // documentation missing in model
    Archived,
    #[allow(missing_docs)] // documentation missing in model
    Compromised,
    #[allow(missing_docs)] // documentation missing in model
    Confirmed,
    #[allow(missing_docs)] // documentation missing in model
    ExternalProvider,
    #[allow(missing_docs)] // documentation missing in model
    ForceChangePassword,
    #[allow(missing_docs)] // documentation missing in model
    ResetRequired,
    #[allow(missing_docs)] // documentation missing in model
    Unconfirmed,
    ///
    /// _Note: `::Unknown` has been renamed to `::UnknownValue`._
    UnknownValue,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for UserStatusType {
    fn from(s: &str) -> Self {
        match s {
            "ARCHIVED" => UserStatusType::Archived,
            "COMPROMISED" => UserStatusType::Compromised,
            "CONFIRMED" => UserStatusType::Confirmed,
            "EXTERNAL_PROVIDER" => UserStatusType::ExternalProvider,
            "FORCE_CHANGE_PASSWORD" => UserStatusType::ForceChangePassword,
            "RESET_REQUIRED" => UserStatusType::ResetRequired,
            "UNCONFIRMED" => UserStatusType::Unconfirmed,
            "UNKNOWN" => UserStatusType::UnknownValue,
            other => UserStatusType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for UserStatusType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(UserStatusType::from(s))
    }
}
impl UserStatusType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            UserStatusType::Archived => "ARCHIVED",
            UserStatusType::Compromised => "COMPROMISED",
            UserStatusType::Confirmed => "CONFIRMED",
            UserStatusType::ExternalProvider => "EXTERNAL_PROVIDER",
            UserStatusType::ForceChangePassword => "FORCE_CHANGE_PASSWORD",
            UserStatusType::ResetRequired => "RESET_REQUIRED",
            UserStatusType::Unconfirmed => "UNCONFIRMED",
            UserStatusType::UnknownValue => "UNKNOWN",
            UserStatusType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ARCHIVED",
            "COMPROMISED",
            "CONFIRMED",
            "EXTERNAL_PROVIDER",
            "FORCE_CHANGE_PASSWORD",
            "RESET_REQUIRED",
            "UNCONFIRMED",
            "UNKNOWN",
        ]
    }
}
impl ::std::convert::AsRef<str> for UserStatusType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl UserStatusType {
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
impl ::std::fmt::Display for UserStatusType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            UserStatusType::Archived => write!(f, "ARCHIVED"),
            UserStatusType::Compromised => write!(f, "COMPROMISED"),
            UserStatusType::Confirmed => write!(f, "CONFIRMED"),
            UserStatusType::ExternalProvider => write!(f, "EXTERNAL_PROVIDER"),
            UserStatusType::ForceChangePassword => write!(f, "FORCE_CHANGE_PASSWORD"),
            UserStatusType::ResetRequired => write!(f, "RESET_REQUIRED"),
            UserStatusType::Unconfirmed => write!(f, "UNCONFIRMED"),
            UserStatusType::UnknownValue => write!(f, "UNKNOWN"),
            UserStatusType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
