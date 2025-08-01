// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `NsState`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let nsstate = unimplemented!();
/// match nsstate {
///     NsState::Deleted => { /* ... */ },
///     NsState::Impaired => { /* ... */ },
///     NsState::Instantiated => { /* ... */ },
///     NsState::InstantiateInProgress => { /* ... */ },
///     NsState::IntentToUpdateInProgress => { /* ... */ },
///     NsState::NotInstantiated => { /* ... */ },
///     NsState::Stopped => { /* ... */ },
///     NsState::TerminateInProgress => { /* ... */ },
///     NsState::Updated => { /* ... */ },
///     NsState::UpdateFailed => { /* ... */ },
///     NsState::UpdateInProgress => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `nsstate` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `NsState::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `NsState::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `NsState::NewFeature` is defined.
/// Specifically, when `nsstate` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `NsState::NewFeature` also yielding `"NewFeature"`.
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
pub enum NsState {
    #[allow(missing_docs)] // documentation missing in model
    Deleted,
    #[allow(missing_docs)] // documentation missing in model
    Impaired,
    #[allow(missing_docs)] // documentation missing in model
    Instantiated,
    #[allow(missing_docs)] // documentation missing in model
    InstantiateInProgress,
    #[allow(missing_docs)] // documentation missing in model
    IntentToUpdateInProgress,
    #[allow(missing_docs)] // documentation missing in model
    NotInstantiated,
    #[allow(missing_docs)] // documentation missing in model
    Stopped,
    #[allow(missing_docs)] // documentation missing in model
    TerminateInProgress,
    #[allow(missing_docs)] // documentation missing in model
    Updated,
    #[allow(missing_docs)] // documentation missing in model
    UpdateFailed,
    #[allow(missing_docs)] // documentation missing in model
    UpdateInProgress,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for NsState {
    fn from(s: &str) -> Self {
        match s {
            "DELETED" => NsState::Deleted,
            "IMPAIRED" => NsState::Impaired,
            "INSTANTIATED" => NsState::Instantiated,
            "INSTANTIATE_IN_PROGRESS" => NsState::InstantiateInProgress,
            "INTENT_TO_UPDATE_IN_PROGRESS" => NsState::IntentToUpdateInProgress,
            "NOT_INSTANTIATED" => NsState::NotInstantiated,
            "STOPPED" => NsState::Stopped,
            "TERMINATE_IN_PROGRESS" => NsState::TerminateInProgress,
            "UPDATED" => NsState::Updated,
            "UPDATE_FAILED" => NsState::UpdateFailed,
            "UPDATE_IN_PROGRESS" => NsState::UpdateInProgress,
            other => NsState::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for NsState {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(NsState::from(s))
    }
}
impl NsState {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            NsState::Deleted => "DELETED",
            NsState::Impaired => "IMPAIRED",
            NsState::Instantiated => "INSTANTIATED",
            NsState::InstantiateInProgress => "INSTANTIATE_IN_PROGRESS",
            NsState::IntentToUpdateInProgress => "INTENT_TO_UPDATE_IN_PROGRESS",
            NsState::NotInstantiated => "NOT_INSTANTIATED",
            NsState::Stopped => "STOPPED",
            NsState::TerminateInProgress => "TERMINATE_IN_PROGRESS",
            NsState::Updated => "UPDATED",
            NsState::UpdateFailed => "UPDATE_FAILED",
            NsState::UpdateInProgress => "UPDATE_IN_PROGRESS",
            NsState::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "DELETED",
            "IMPAIRED",
            "INSTANTIATED",
            "INSTANTIATE_IN_PROGRESS",
            "INTENT_TO_UPDATE_IN_PROGRESS",
            "NOT_INSTANTIATED",
            "STOPPED",
            "TERMINATE_IN_PROGRESS",
            "UPDATED",
            "UPDATE_FAILED",
            "UPDATE_IN_PROGRESS",
        ]
    }
}
impl ::std::convert::AsRef<str> for NsState {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl NsState {
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
impl ::std::fmt::Display for NsState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            NsState::Deleted => write!(f, "DELETED"),
            NsState::Impaired => write!(f, "IMPAIRED"),
            NsState::Instantiated => write!(f, "INSTANTIATED"),
            NsState::InstantiateInProgress => write!(f, "INSTANTIATE_IN_PROGRESS"),
            NsState::IntentToUpdateInProgress => write!(f, "INTENT_TO_UPDATE_IN_PROGRESS"),
            NsState::NotInstantiated => write!(f, "NOT_INSTANTIATED"),
            NsState::Stopped => write!(f, "STOPPED"),
            NsState::TerminateInProgress => write!(f, "TERMINATE_IN_PROGRESS"),
            NsState::Updated => write!(f, "UPDATED"),
            NsState::UpdateFailed => write!(f, "UPDATE_FAILED"),
            NsState::UpdateInProgress => write!(f, "UPDATE_IN_PROGRESS"),
            NsState::Unknown(value) => write!(f, "{}", value),
        }
    }
}
