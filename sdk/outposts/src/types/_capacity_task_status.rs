// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `CapacityTaskStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let capacitytaskstatus = unimplemented!();
/// match capacitytaskstatus {
///     CapacityTaskStatus::CancellationInProgress => { /* ... */ },
///     CapacityTaskStatus::Cancelled => { /* ... */ },
///     CapacityTaskStatus::Completed => { /* ... */ },
///     CapacityTaskStatus::Failed => { /* ... */ },
///     CapacityTaskStatus::InProgress => { /* ... */ },
///     CapacityTaskStatus::Requested => { /* ... */ },
///     CapacityTaskStatus::WaitingForEvacuation => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `capacitytaskstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `CapacityTaskStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `CapacityTaskStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `CapacityTaskStatus::NewFeature` is defined.
/// Specifically, when `capacitytaskstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `CapacityTaskStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum CapacityTaskStatus {
    #[allow(missing_docs)] // documentation missing in model
    CancellationInProgress,
    #[allow(missing_docs)] // documentation missing in model
    Cancelled,
    #[allow(missing_docs)] // documentation missing in model
    Completed,
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    #[allow(missing_docs)] // documentation missing in model
    InProgress,
    #[allow(missing_docs)] // documentation missing in model
    Requested,
    #[allow(missing_docs)] // documentation missing in model
    WaitingForEvacuation,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for CapacityTaskStatus {
    fn from(s: &str) -> Self {
        match s {
            "CANCELLATION_IN_PROGRESS" => CapacityTaskStatus::CancellationInProgress,
            "CANCELLED" => CapacityTaskStatus::Cancelled,
            "COMPLETED" => CapacityTaskStatus::Completed,
            "FAILED" => CapacityTaskStatus::Failed,
            "IN_PROGRESS" => CapacityTaskStatus::InProgress,
            "REQUESTED" => CapacityTaskStatus::Requested,
            "WAITING_FOR_EVACUATION" => CapacityTaskStatus::WaitingForEvacuation,
            other => CapacityTaskStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for CapacityTaskStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(CapacityTaskStatus::from(s))
    }
}
impl CapacityTaskStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            CapacityTaskStatus::CancellationInProgress => "CANCELLATION_IN_PROGRESS",
            CapacityTaskStatus::Cancelled => "CANCELLED",
            CapacityTaskStatus::Completed => "COMPLETED",
            CapacityTaskStatus::Failed => "FAILED",
            CapacityTaskStatus::InProgress => "IN_PROGRESS",
            CapacityTaskStatus::Requested => "REQUESTED",
            CapacityTaskStatus::WaitingForEvacuation => "WAITING_FOR_EVACUATION",
            CapacityTaskStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "CANCELLATION_IN_PROGRESS",
            "CANCELLED",
            "COMPLETED",
            "FAILED",
            "IN_PROGRESS",
            "REQUESTED",
            "WAITING_FOR_EVACUATION",
        ]
    }
}
impl ::std::convert::AsRef<str> for CapacityTaskStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl CapacityTaskStatus {
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
impl ::std::fmt::Display for CapacityTaskStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            CapacityTaskStatus::CancellationInProgress => write!(f, "CANCELLATION_IN_PROGRESS"),
            CapacityTaskStatus::Cancelled => write!(f, "CANCELLED"),
            CapacityTaskStatus::Completed => write!(f, "COMPLETED"),
            CapacityTaskStatus::Failed => write!(f, "FAILED"),
            CapacityTaskStatus::InProgress => write!(f, "IN_PROGRESS"),
            CapacityTaskStatus::Requested => write!(f, "REQUESTED"),
            CapacityTaskStatus::WaitingForEvacuation => write!(f, "WAITING_FOR_EVACUATION"),
            CapacityTaskStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
