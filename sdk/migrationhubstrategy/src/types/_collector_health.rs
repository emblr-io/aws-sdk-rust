// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `CollectorHealth`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let collectorhealth = unimplemented!();
/// match collectorhealth {
///     CollectorHealth::CollectorHealthy => { /* ... */ },
///     CollectorHealth::CollectorUnhealthy => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `collectorhealth` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `CollectorHealth::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `CollectorHealth::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `CollectorHealth::NewFeature` is defined.
/// Specifically, when `collectorhealth` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `CollectorHealth::NewFeature` also yielding `"NewFeature"`.
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
pub enum CollectorHealth {
    #[allow(missing_docs)] // documentation missing in model
    CollectorHealthy,
    #[allow(missing_docs)] // documentation missing in model
    CollectorUnhealthy,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for CollectorHealth {
    fn from(s: &str) -> Self {
        match s {
            "COLLECTOR_HEALTHY" => CollectorHealth::CollectorHealthy,
            "COLLECTOR_UNHEALTHY" => CollectorHealth::CollectorUnhealthy,
            other => CollectorHealth::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for CollectorHealth {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(CollectorHealth::from(s))
    }
}
impl CollectorHealth {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            CollectorHealth::CollectorHealthy => "COLLECTOR_HEALTHY",
            CollectorHealth::CollectorUnhealthy => "COLLECTOR_UNHEALTHY",
            CollectorHealth::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["COLLECTOR_HEALTHY", "COLLECTOR_UNHEALTHY"]
    }
}
impl ::std::convert::AsRef<str> for CollectorHealth {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl CollectorHealth {
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
impl ::std::fmt::Display for CollectorHealth {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            CollectorHealth::CollectorHealthy => write!(f, "COLLECTOR_HEALTHY"),
            CollectorHealth::CollectorUnhealthy => write!(f, "COLLECTOR_UNHEALTHY"),
            CollectorHealth::Unknown(value) => write!(f, "{}", value),
        }
    }
}
