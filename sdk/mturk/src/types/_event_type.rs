// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `EventType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let eventtype = unimplemented!();
/// match eventtype {
///     EventType::AssignmentAbandoned => { /* ... */ },
///     EventType::AssignmentAccepted => { /* ... */ },
///     EventType::AssignmentApproved => { /* ... */ },
///     EventType::AssignmentRejected => { /* ... */ },
///     EventType::AssignmentReturned => { /* ... */ },
///     EventType::AssignmentSubmitted => { /* ... */ },
///     EventType::HitCreated => { /* ... */ },
///     EventType::HitDisposed => { /* ... */ },
///     EventType::HitExpired => { /* ... */ },
///     EventType::HitExtended => { /* ... */ },
///     EventType::HitReviewable => { /* ... */ },
///     EventType::Ping => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `eventtype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `EventType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `EventType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `EventType::NewFeature` is defined.
/// Specifically, when `eventtype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `EventType::NewFeature` also yielding `"NewFeature"`.
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
pub enum EventType {
    #[allow(missing_docs)] // documentation missing in model
    AssignmentAbandoned,
    #[allow(missing_docs)] // documentation missing in model
    AssignmentAccepted,
    #[allow(missing_docs)] // documentation missing in model
    AssignmentApproved,
    #[allow(missing_docs)] // documentation missing in model
    AssignmentRejected,
    #[allow(missing_docs)] // documentation missing in model
    AssignmentReturned,
    #[allow(missing_docs)] // documentation missing in model
    AssignmentSubmitted,
    #[allow(missing_docs)] // documentation missing in model
    HitCreated,
    #[allow(missing_docs)] // documentation missing in model
    HitDisposed,
    #[allow(missing_docs)] // documentation missing in model
    HitExpired,
    #[allow(missing_docs)] // documentation missing in model
    HitExtended,
    #[allow(missing_docs)] // documentation missing in model
    HitReviewable,
    #[allow(missing_docs)] // documentation missing in model
    Ping,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for EventType {
    fn from(s: &str) -> Self {
        match s {
            "AssignmentAbandoned" => EventType::AssignmentAbandoned,
            "AssignmentAccepted" => EventType::AssignmentAccepted,
            "AssignmentApproved" => EventType::AssignmentApproved,
            "AssignmentRejected" => EventType::AssignmentRejected,
            "AssignmentReturned" => EventType::AssignmentReturned,
            "AssignmentSubmitted" => EventType::AssignmentSubmitted,
            "HITCreated" => EventType::HitCreated,
            "HITDisposed" => EventType::HitDisposed,
            "HITExpired" => EventType::HitExpired,
            "HITExtended" => EventType::HitExtended,
            "HITReviewable" => EventType::HitReviewable,
            "Ping" => EventType::Ping,
            other => EventType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for EventType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(EventType::from(s))
    }
}
impl EventType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            EventType::AssignmentAbandoned => "AssignmentAbandoned",
            EventType::AssignmentAccepted => "AssignmentAccepted",
            EventType::AssignmentApproved => "AssignmentApproved",
            EventType::AssignmentRejected => "AssignmentRejected",
            EventType::AssignmentReturned => "AssignmentReturned",
            EventType::AssignmentSubmitted => "AssignmentSubmitted",
            EventType::HitCreated => "HITCreated",
            EventType::HitDisposed => "HITDisposed",
            EventType::HitExpired => "HITExpired",
            EventType::HitExtended => "HITExtended",
            EventType::HitReviewable => "HITReviewable",
            EventType::Ping => "Ping",
            EventType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AssignmentAbandoned",
            "AssignmentAccepted",
            "AssignmentApproved",
            "AssignmentRejected",
            "AssignmentReturned",
            "AssignmentSubmitted",
            "HITCreated",
            "HITDisposed",
            "HITExpired",
            "HITExtended",
            "HITReviewable",
            "Ping",
        ]
    }
}
impl ::std::convert::AsRef<str> for EventType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl EventType {
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
impl ::std::fmt::Display for EventType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            EventType::AssignmentAbandoned => write!(f, "AssignmentAbandoned"),
            EventType::AssignmentAccepted => write!(f, "AssignmentAccepted"),
            EventType::AssignmentApproved => write!(f, "AssignmentApproved"),
            EventType::AssignmentRejected => write!(f, "AssignmentRejected"),
            EventType::AssignmentReturned => write!(f, "AssignmentReturned"),
            EventType::AssignmentSubmitted => write!(f, "AssignmentSubmitted"),
            EventType::HitCreated => write!(f, "HITCreated"),
            EventType::HitDisposed => write!(f, "HITDisposed"),
            EventType::HitExpired => write!(f, "HITExpired"),
            EventType::HitExtended => write!(f, "HITExtended"),
            EventType::HitReviewable => write!(f, "HITReviewable"),
            EventType::Ping => write!(f, "Ping"),
            EventType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
