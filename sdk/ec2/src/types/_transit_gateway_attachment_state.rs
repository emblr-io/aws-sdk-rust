// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `TransitGatewayAttachmentState`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let transitgatewayattachmentstate = unimplemented!();
/// match transitgatewayattachmentstate {
///     TransitGatewayAttachmentState::Available => { /* ... */ },
///     TransitGatewayAttachmentState::Deleted => { /* ... */ },
///     TransitGatewayAttachmentState::Deleting => { /* ... */ },
///     TransitGatewayAttachmentState::Failed => { /* ... */ },
///     TransitGatewayAttachmentState::Failing => { /* ... */ },
///     TransitGatewayAttachmentState::Initiating => { /* ... */ },
///     TransitGatewayAttachmentState::InitiatingRequest => { /* ... */ },
///     TransitGatewayAttachmentState::Modifying => { /* ... */ },
///     TransitGatewayAttachmentState::Pending => { /* ... */ },
///     TransitGatewayAttachmentState::PendingAcceptance => { /* ... */ },
///     TransitGatewayAttachmentState::Rejected => { /* ... */ },
///     TransitGatewayAttachmentState::Rejecting => { /* ... */ },
///     TransitGatewayAttachmentState::RollingBack => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `transitgatewayattachmentstate` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `TransitGatewayAttachmentState::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `TransitGatewayAttachmentState::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `TransitGatewayAttachmentState::NewFeature` is defined.
/// Specifically, when `transitgatewayattachmentstate` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `TransitGatewayAttachmentState::NewFeature` also yielding `"NewFeature"`.
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
pub enum TransitGatewayAttachmentState {
    #[allow(missing_docs)] // documentation missing in model
    Available,
    #[allow(missing_docs)] // documentation missing in model
    Deleted,
    #[allow(missing_docs)] // documentation missing in model
    Deleting,
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    #[allow(missing_docs)] // documentation missing in model
    Failing,
    #[allow(missing_docs)] // documentation missing in model
    Initiating,
    #[allow(missing_docs)] // documentation missing in model
    InitiatingRequest,
    #[allow(missing_docs)] // documentation missing in model
    Modifying,
    #[allow(missing_docs)] // documentation missing in model
    Pending,
    #[allow(missing_docs)] // documentation missing in model
    PendingAcceptance,
    #[allow(missing_docs)] // documentation missing in model
    Rejected,
    #[allow(missing_docs)] // documentation missing in model
    Rejecting,
    #[allow(missing_docs)] // documentation missing in model
    RollingBack,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for TransitGatewayAttachmentState {
    fn from(s: &str) -> Self {
        match s {
            "available" => TransitGatewayAttachmentState::Available,
            "deleted" => TransitGatewayAttachmentState::Deleted,
            "deleting" => TransitGatewayAttachmentState::Deleting,
            "failed" => TransitGatewayAttachmentState::Failed,
            "failing" => TransitGatewayAttachmentState::Failing,
            "initiating" => TransitGatewayAttachmentState::Initiating,
            "initiatingRequest" => TransitGatewayAttachmentState::InitiatingRequest,
            "modifying" => TransitGatewayAttachmentState::Modifying,
            "pending" => TransitGatewayAttachmentState::Pending,
            "pendingAcceptance" => TransitGatewayAttachmentState::PendingAcceptance,
            "rejected" => TransitGatewayAttachmentState::Rejected,
            "rejecting" => TransitGatewayAttachmentState::Rejecting,
            "rollingBack" => TransitGatewayAttachmentState::RollingBack,
            other => TransitGatewayAttachmentState::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for TransitGatewayAttachmentState {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(TransitGatewayAttachmentState::from(s))
    }
}
impl TransitGatewayAttachmentState {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            TransitGatewayAttachmentState::Available => "available",
            TransitGatewayAttachmentState::Deleted => "deleted",
            TransitGatewayAttachmentState::Deleting => "deleting",
            TransitGatewayAttachmentState::Failed => "failed",
            TransitGatewayAttachmentState::Failing => "failing",
            TransitGatewayAttachmentState::Initiating => "initiating",
            TransitGatewayAttachmentState::InitiatingRequest => "initiatingRequest",
            TransitGatewayAttachmentState::Modifying => "modifying",
            TransitGatewayAttachmentState::Pending => "pending",
            TransitGatewayAttachmentState::PendingAcceptance => "pendingAcceptance",
            TransitGatewayAttachmentState::Rejected => "rejected",
            TransitGatewayAttachmentState::Rejecting => "rejecting",
            TransitGatewayAttachmentState::RollingBack => "rollingBack",
            TransitGatewayAttachmentState::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "available",
            "deleted",
            "deleting",
            "failed",
            "failing",
            "initiating",
            "initiatingRequest",
            "modifying",
            "pending",
            "pendingAcceptance",
            "rejected",
            "rejecting",
            "rollingBack",
        ]
    }
}
impl ::std::convert::AsRef<str> for TransitGatewayAttachmentState {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl TransitGatewayAttachmentState {
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
impl ::std::fmt::Display for TransitGatewayAttachmentState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            TransitGatewayAttachmentState::Available => write!(f, "available"),
            TransitGatewayAttachmentState::Deleted => write!(f, "deleted"),
            TransitGatewayAttachmentState::Deleting => write!(f, "deleting"),
            TransitGatewayAttachmentState::Failed => write!(f, "failed"),
            TransitGatewayAttachmentState::Failing => write!(f, "failing"),
            TransitGatewayAttachmentState::Initiating => write!(f, "initiating"),
            TransitGatewayAttachmentState::InitiatingRequest => write!(f, "initiatingRequest"),
            TransitGatewayAttachmentState::Modifying => write!(f, "modifying"),
            TransitGatewayAttachmentState::Pending => write!(f, "pending"),
            TransitGatewayAttachmentState::PendingAcceptance => write!(f, "pendingAcceptance"),
            TransitGatewayAttachmentState::Rejected => write!(f, "rejected"),
            TransitGatewayAttachmentState::Rejecting => write!(f, "rejecting"),
            TransitGatewayAttachmentState::RollingBack => write!(f, "rollingBack"),
            TransitGatewayAttachmentState::Unknown(value) => write!(f, "{}", value),
        }
    }
}
