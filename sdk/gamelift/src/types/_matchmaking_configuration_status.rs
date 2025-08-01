// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `MatchmakingConfigurationStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let matchmakingconfigurationstatus = unimplemented!();
/// match matchmakingconfigurationstatus {
///     MatchmakingConfigurationStatus::Cancelled => { /* ... */ },
///     MatchmakingConfigurationStatus::Completed => { /* ... */ },
///     MatchmakingConfigurationStatus::Failed => { /* ... */ },
///     MatchmakingConfigurationStatus::Placing => { /* ... */ },
///     MatchmakingConfigurationStatus::Queued => { /* ... */ },
///     MatchmakingConfigurationStatus::RequiresAcceptance => { /* ... */ },
///     MatchmakingConfigurationStatus::Searching => { /* ... */ },
///     MatchmakingConfigurationStatus::TimedOut => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `matchmakingconfigurationstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `MatchmakingConfigurationStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `MatchmakingConfigurationStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `MatchmakingConfigurationStatus::NewFeature` is defined.
/// Specifically, when `matchmakingconfigurationstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `MatchmakingConfigurationStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum MatchmakingConfigurationStatus {
    #[allow(missing_docs)] // documentation missing in model
    Cancelled,
    #[allow(missing_docs)] // documentation missing in model
    Completed,
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    #[allow(missing_docs)] // documentation missing in model
    Placing,
    #[allow(missing_docs)] // documentation missing in model
    Queued,
    #[allow(missing_docs)] // documentation missing in model
    RequiresAcceptance,
    #[allow(missing_docs)] // documentation missing in model
    Searching,
    #[allow(missing_docs)] // documentation missing in model
    TimedOut,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for MatchmakingConfigurationStatus {
    fn from(s: &str) -> Self {
        match s {
            "CANCELLED" => MatchmakingConfigurationStatus::Cancelled,
            "COMPLETED" => MatchmakingConfigurationStatus::Completed,
            "FAILED" => MatchmakingConfigurationStatus::Failed,
            "PLACING" => MatchmakingConfigurationStatus::Placing,
            "QUEUED" => MatchmakingConfigurationStatus::Queued,
            "REQUIRES_ACCEPTANCE" => MatchmakingConfigurationStatus::RequiresAcceptance,
            "SEARCHING" => MatchmakingConfigurationStatus::Searching,
            "TIMED_OUT" => MatchmakingConfigurationStatus::TimedOut,
            other => MatchmakingConfigurationStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for MatchmakingConfigurationStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(MatchmakingConfigurationStatus::from(s))
    }
}
impl MatchmakingConfigurationStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            MatchmakingConfigurationStatus::Cancelled => "CANCELLED",
            MatchmakingConfigurationStatus::Completed => "COMPLETED",
            MatchmakingConfigurationStatus::Failed => "FAILED",
            MatchmakingConfigurationStatus::Placing => "PLACING",
            MatchmakingConfigurationStatus::Queued => "QUEUED",
            MatchmakingConfigurationStatus::RequiresAcceptance => "REQUIRES_ACCEPTANCE",
            MatchmakingConfigurationStatus::Searching => "SEARCHING",
            MatchmakingConfigurationStatus::TimedOut => "TIMED_OUT",
            MatchmakingConfigurationStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "CANCELLED",
            "COMPLETED",
            "FAILED",
            "PLACING",
            "QUEUED",
            "REQUIRES_ACCEPTANCE",
            "SEARCHING",
            "TIMED_OUT",
        ]
    }
}
impl ::std::convert::AsRef<str> for MatchmakingConfigurationStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl MatchmakingConfigurationStatus {
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
impl ::std::fmt::Display for MatchmakingConfigurationStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            MatchmakingConfigurationStatus::Cancelled => write!(f, "CANCELLED"),
            MatchmakingConfigurationStatus::Completed => write!(f, "COMPLETED"),
            MatchmakingConfigurationStatus::Failed => write!(f, "FAILED"),
            MatchmakingConfigurationStatus::Placing => write!(f, "PLACING"),
            MatchmakingConfigurationStatus::Queued => write!(f, "QUEUED"),
            MatchmakingConfigurationStatus::RequiresAcceptance => write!(f, "REQUIRES_ACCEPTANCE"),
            MatchmakingConfigurationStatus::Searching => write!(f, "SEARCHING"),
            MatchmakingConfigurationStatus::TimedOut => write!(f, "TIMED_OUT"),
            MatchmakingConfigurationStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
