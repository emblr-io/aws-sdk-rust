// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ReceivedStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let receivedstatus = unimplemented!();
/// match receivedstatus {
///     ReceivedStatus::Active => { /* ... */ },
///     ReceivedStatus::Deleted => { /* ... */ },
///     ReceivedStatus::Disabled => { /* ... */ },
///     ReceivedStatus::FailedWorkflow => { /* ... */ },
///     ReceivedStatus::PendingAccept => { /* ... */ },
///     ReceivedStatus::PendingWorkflow => { /* ... */ },
///     ReceivedStatus::Rejected => { /* ... */ },
///     ReceivedStatus::WorkflowCompleted => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `receivedstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ReceivedStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ReceivedStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ReceivedStatus::NewFeature` is defined.
/// Specifically, when `receivedstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ReceivedStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum ReceivedStatus {
    #[allow(missing_docs)] // documentation missing in model
    Active,
    #[allow(missing_docs)] // documentation missing in model
    Deleted,
    #[allow(missing_docs)] // documentation missing in model
    Disabled,
    #[allow(missing_docs)] // documentation missing in model
    FailedWorkflow,
    #[allow(missing_docs)] // documentation missing in model
    PendingAccept,
    #[allow(missing_docs)] // documentation missing in model
    PendingWorkflow,
    #[allow(missing_docs)] // documentation missing in model
    Rejected,
    #[allow(missing_docs)] // documentation missing in model
    WorkflowCompleted,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ReceivedStatus {
    fn from(s: &str) -> Self {
        match s {
            "ACTIVE" => ReceivedStatus::Active,
            "DELETED" => ReceivedStatus::Deleted,
            "DISABLED" => ReceivedStatus::Disabled,
            "FAILED_WORKFLOW" => ReceivedStatus::FailedWorkflow,
            "PENDING_ACCEPT" => ReceivedStatus::PendingAccept,
            "PENDING_WORKFLOW" => ReceivedStatus::PendingWorkflow,
            "REJECTED" => ReceivedStatus::Rejected,
            "WORKFLOW_COMPLETED" => ReceivedStatus::WorkflowCompleted,
            other => ReceivedStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ReceivedStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ReceivedStatus::from(s))
    }
}
impl ReceivedStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ReceivedStatus::Active => "ACTIVE",
            ReceivedStatus::Deleted => "DELETED",
            ReceivedStatus::Disabled => "DISABLED",
            ReceivedStatus::FailedWorkflow => "FAILED_WORKFLOW",
            ReceivedStatus::PendingAccept => "PENDING_ACCEPT",
            ReceivedStatus::PendingWorkflow => "PENDING_WORKFLOW",
            ReceivedStatus::Rejected => "REJECTED",
            ReceivedStatus::WorkflowCompleted => "WORKFLOW_COMPLETED",
            ReceivedStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACTIVE",
            "DELETED",
            "DISABLED",
            "FAILED_WORKFLOW",
            "PENDING_ACCEPT",
            "PENDING_WORKFLOW",
            "REJECTED",
            "WORKFLOW_COMPLETED",
        ]
    }
}
impl ::std::convert::AsRef<str> for ReceivedStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ReceivedStatus {
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
impl ::std::fmt::Display for ReceivedStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ReceivedStatus::Active => write!(f, "ACTIVE"),
            ReceivedStatus::Deleted => write!(f, "DELETED"),
            ReceivedStatus::Disabled => write!(f, "DISABLED"),
            ReceivedStatus::FailedWorkflow => write!(f, "FAILED_WORKFLOW"),
            ReceivedStatus::PendingAccept => write!(f, "PENDING_ACCEPT"),
            ReceivedStatus::PendingWorkflow => write!(f, "PENDING_WORKFLOW"),
            ReceivedStatus::Rejected => write!(f, "REJECTED"),
            ReceivedStatus::WorkflowCompleted => write!(f, "WORKFLOW_COMPLETED"),
            ReceivedStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
