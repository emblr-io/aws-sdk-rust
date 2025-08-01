// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AssociateResourceErrorReason`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let associateresourceerrorreason = unimplemented!();
/// match associateresourceerrorreason {
///     AssociateResourceErrorReason::IllegalCustomlineitem => { /* ... */ },
///     AssociateResourceErrorReason::InternalServerException => { /* ... */ },
///     AssociateResourceErrorReason::InvalidArn => { /* ... */ },
///     AssociateResourceErrorReason::InvalidBillingPeriodRange => { /* ... */ },
///     AssociateResourceErrorReason::ServiceLimitExceeded => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `associateresourceerrorreason` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AssociateResourceErrorReason::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AssociateResourceErrorReason::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AssociateResourceErrorReason::NewFeature` is defined.
/// Specifically, when `associateresourceerrorreason` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AssociateResourceErrorReason::NewFeature` also yielding `"NewFeature"`.
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
pub enum AssociateResourceErrorReason {
    #[allow(missing_docs)] // documentation missing in model
    IllegalCustomlineitem,
    #[allow(missing_docs)] // documentation missing in model
    InternalServerException,
    #[allow(missing_docs)] // documentation missing in model
    InvalidArn,
    #[allow(missing_docs)] // documentation missing in model
    InvalidBillingPeriodRange,
    #[allow(missing_docs)] // documentation missing in model
    ServiceLimitExceeded,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AssociateResourceErrorReason {
    fn from(s: &str) -> Self {
        match s {
            "ILLEGAL_CUSTOMLINEITEM" => AssociateResourceErrorReason::IllegalCustomlineitem,
            "INTERNAL_SERVER_EXCEPTION" => AssociateResourceErrorReason::InternalServerException,
            "INVALID_ARN" => AssociateResourceErrorReason::InvalidArn,
            "INVALID_BILLING_PERIOD_RANGE" => AssociateResourceErrorReason::InvalidBillingPeriodRange,
            "SERVICE_LIMIT_EXCEEDED" => AssociateResourceErrorReason::ServiceLimitExceeded,
            other => AssociateResourceErrorReason::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AssociateResourceErrorReason {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AssociateResourceErrorReason::from(s))
    }
}
impl AssociateResourceErrorReason {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AssociateResourceErrorReason::IllegalCustomlineitem => "ILLEGAL_CUSTOMLINEITEM",
            AssociateResourceErrorReason::InternalServerException => "INTERNAL_SERVER_EXCEPTION",
            AssociateResourceErrorReason::InvalidArn => "INVALID_ARN",
            AssociateResourceErrorReason::InvalidBillingPeriodRange => "INVALID_BILLING_PERIOD_RANGE",
            AssociateResourceErrorReason::ServiceLimitExceeded => "SERVICE_LIMIT_EXCEEDED",
            AssociateResourceErrorReason::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ILLEGAL_CUSTOMLINEITEM",
            "INTERNAL_SERVER_EXCEPTION",
            "INVALID_ARN",
            "INVALID_BILLING_PERIOD_RANGE",
            "SERVICE_LIMIT_EXCEEDED",
        ]
    }
}
impl ::std::convert::AsRef<str> for AssociateResourceErrorReason {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AssociateResourceErrorReason {
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
impl ::std::fmt::Display for AssociateResourceErrorReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AssociateResourceErrorReason::IllegalCustomlineitem => write!(f, "ILLEGAL_CUSTOMLINEITEM"),
            AssociateResourceErrorReason::InternalServerException => write!(f, "INTERNAL_SERVER_EXCEPTION"),
            AssociateResourceErrorReason::InvalidArn => write!(f, "INVALID_ARN"),
            AssociateResourceErrorReason::InvalidBillingPeriodRange => write!(f, "INVALID_BILLING_PERIOD_RANGE"),
            AssociateResourceErrorReason::ServiceLimitExceeded => write!(f, "SERVICE_LIMIT_EXCEEDED"),
            AssociateResourceErrorReason::Unknown(value) => write!(f, "{}", value),
        }
    }
}
