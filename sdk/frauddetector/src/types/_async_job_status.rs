// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AsyncJobStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let asyncjobstatus = unimplemented!();
/// match asyncjobstatus {
///     AsyncJobStatus::Canceled => { /* ... */ },
///     AsyncJobStatus::CancelInProgress => { /* ... */ },
///     AsyncJobStatus::Complete => { /* ... */ },
///     AsyncJobStatus::Failed => { /* ... */ },
///     AsyncJobStatus::InProgress => { /* ... */ },
///     AsyncJobStatus::InProgressInitializing => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `asyncjobstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AsyncJobStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AsyncJobStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AsyncJobStatus::NewFeature` is defined.
/// Specifically, when `asyncjobstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AsyncJobStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum AsyncJobStatus {
    #[allow(missing_docs)] // documentation missing in model
    Canceled,
    #[allow(missing_docs)] // documentation missing in model
    CancelInProgress,
    #[allow(missing_docs)] // documentation missing in model
    Complete,
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    #[allow(missing_docs)] // documentation missing in model
    InProgress,
    #[allow(missing_docs)] // documentation missing in model
    InProgressInitializing,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AsyncJobStatus {
    fn from(s: &str) -> Self {
        match s {
            "CANCELED" => AsyncJobStatus::Canceled,
            "CANCEL_IN_PROGRESS" => AsyncJobStatus::CancelInProgress,
            "COMPLETE" => AsyncJobStatus::Complete,
            "FAILED" => AsyncJobStatus::Failed,
            "IN_PROGRESS" => AsyncJobStatus::InProgress,
            "IN_PROGRESS_INITIALIZING" => AsyncJobStatus::InProgressInitializing,
            other => AsyncJobStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AsyncJobStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AsyncJobStatus::from(s))
    }
}
impl AsyncJobStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AsyncJobStatus::Canceled => "CANCELED",
            AsyncJobStatus::CancelInProgress => "CANCEL_IN_PROGRESS",
            AsyncJobStatus::Complete => "COMPLETE",
            AsyncJobStatus::Failed => "FAILED",
            AsyncJobStatus::InProgress => "IN_PROGRESS",
            AsyncJobStatus::InProgressInitializing => "IN_PROGRESS_INITIALIZING",
            AsyncJobStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "CANCELED",
            "CANCEL_IN_PROGRESS",
            "COMPLETE",
            "FAILED",
            "IN_PROGRESS",
            "IN_PROGRESS_INITIALIZING",
        ]
    }
}
impl ::std::convert::AsRef<str> for AsyncJobStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AsyncJobStatus {
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
impl ::std::fmt::Display for AsyncJobStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AsyncJobStatus::Canceled => write!(f, "CANCELED"),
            AsyncJobStatus::CancelInProgress => write!(f, "CANCEL_IN_PROGRESS"),
            AsyncJobStatus::Complete => write!(f, "COMPLETE"),
            AsyncJobStatus::Failed => write!(f, "FAILED"),
            AsyncJobStatus::InProgress => write!(f, "IN_PROGRESS"),
            AsyncJobStatus::InProgressInitializing => write!(f, "IN_PROGRESS_INITIALIZING"),
            AsyncJobStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
