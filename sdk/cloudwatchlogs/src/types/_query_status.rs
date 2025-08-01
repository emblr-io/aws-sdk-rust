// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `QueryStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let querystatus = unimplemented!();
/// match querystatus {
///     QueryStatus::Cancelled => { /* ... */ },
///     QueryStatus::Complete => { /* ... */ },
///     QueryStatus::Failed => { /* ... */ },
///     QueryStatus::Running => { /* ... */ },
///     QueryStatus::Scheduled => { /* ... */ },
///     QueryStatus::Timeout => { /* ... */ },
///     QueryStatus::UnknownValue => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `querystatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `QueryStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `QueryStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `QueryStatus::NewFeature` is defined.
/// Specifically, when `querystatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `QueryStatus::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
///
/// _Note: `QueryStatus::Unknown` has been renamed to `::UnknownValue`._
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum QueryStatus {
    #[allow(missing_docs)] // documentation missing in model
    Cancelled,
    #[allow(missing_docs)] // documentation missing in model
    Complete,
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    #[allow(missing_docs)] // documentation missing in model
    Running,
    #[allow(missing_docs)] // documentation missing in model
    Scheduled,
    #[allow(missing_docs)] // documentation missing in model
    Timeout,
    ///
    /// _Note: `::Unknown` has been renamed to `::UnknownValue`._
    UnknownValue,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for QueryStatus {
    fn from(s: &str) -> Self {
        match s {
            "Cancelled" => QueryStatus::Cancelled,
            "Complete" => QueryStatus::Complete,
            "Failed" => QueryStatus::Failed,
            "Running" => QueryStatus::Running,
            "Scheduled" => QueryStatus::Scheduled,
            "Timeout" => QueryStatus::Timeout,
            "Unknown" => QueryStatus::UnknownValue,
            other => QueryStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for QueryStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(QueryStatus::from(s))
    }
}
impl QueryStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            QueryStatus::Cancelled => "Cancelled",
            QueryStatus::Complete => "Complete",
            QueryStatus::Failed => "Failed",
            QueryStatus::Running => "Running",
            QueryStatus::Scheduled => "Scheduled",
            QueryStatus::Timeout => "Timeout",
            QueryStatus::UnknownValue => "Unknown",
            QueryStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["Cancelled", "Complete", "Failed", "Running", "Scheduled", "Timeout", "Unknown"]
    }
}
impl ::std::convert::AsRef<str> for QueryStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl QueryStatus {
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
impl ::std::fmt::Display for QueryStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            QueryStatus::Cancelled => write!(f, "Cancelled"),
            QueryStatus::Complete => write!(f, "Complete"),
            QueryStatus::Failed => write!(f, "Failed"),
            QueryStatus::Running => write!(f, "Running"),
            QueryStatus::Scheduled => write!(f, "Scheduled"),
            QueryStatus::Timeout => write!(f, "Timeout"),
            QueryStatus::UnknownValue => write!(f, "Unknown"),
            QueryStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
