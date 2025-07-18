// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `RoutePedestrianTravelStepType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let routepedestriantravelsteptype = unimplemented!();
/// match routepedestriantravelsteptype {
///     RoutePedestrianTravelStepType::Arrive => { /* ... */ },
///     RoutePedestrianTravelStepType::Continue => { /* ... */ },
///     RoutePedestrianTravelStepType::Depart => { /* ... */ },
///     RoutePedestrianTravelStepType::Exit => { /* ... */ },
///     RoutePedestrianTravelStepType::Keep => { /* ... */ },
///     RoutePedestrianTravelStepType::Ramp => { /* ... */ },
///     RoutePedestrianTravelStepType::RoundaboutEnter => { /* ... */ },
///     RoutePedestrianTravelStepType::RoundaboutExit => { /* ... */ },
///     RoutePedestrianTravelStepType::RoundaboutPass => { /* ... */ },
///     RoutePedestrianTravelStepType::Turn => { /* ... */ },
///     RoutePedestrianTravelStepType::UTurn => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `routepedestriantravelsteptype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `RoutePedestrianTravelStepType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `RoutePedestrianTravelStepType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `RoutePedestrianTravelStepType::NewFeature` is defined.
/// Specifically, when `routepedestriantravelsteptype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `RoutePedestrianTravelStepType::NewFeature` also yielding `"NewFeature"`.
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
pub enum RoutePedestrianTravelStepType {
    #[allow(missing_docs)] // documentation missing in model
    Arrive,
    #[allow(missing_docs)] // documentation missing in model
    Continue,
    #[allow(missing_docs)] // documentation missing in model
    Depart,
    #[allow(missing_docs)] // documentation missing in model
    Exit,
    #[allow(missing_docs)] // documentation missing in model
    Keep,
    #[allow(missing_docs)] // documentation missing in model
    Ramp,
    #[allow(missing_docs)] // documentation missing in model
    RoundaboutEnter,
    #[allow(missing_docs)] // documentation missing in model
    RoundaboutExit,
    #[allow(missing_docs)] // documentation missing in model
    RoundaboutPass,
    #[allow(missing_docs)] // documentation missing in model
    Turn,
    #[allow(missing_docs)] // documentation missing in model
    UTurn,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for RoutePedestrianTravelStepType {
    fn from(s: &str) -> Self {
        match s {
            "Arrive" => RoutePedestrianTravelStepType::Arrive,
            "Continue" => RoutePedestrianTravelStepType::Continue,
            "Depart" => RoutePedestrianTravelStepType::Depart,
            "Exit" => RoutePedestrianTravelStepType::Exit,
            "Keep" => RoutePedestrianTravelStepType::Keep,
            "Ramp" => RoutePedestrianTravelStepType::Ramp,
            "RoundaboutEnter" => RoutePedestrianTravelStepType::RoundaboutEnter,
            "RoundaboutExit" => RoutePedestrianTravelStepType::RoundaboutExit,
            "RoundaboutPass" => RoutePedestrianTravelStepType::RoundaboutPass,
            "Turn" => RoutePedestrianTravelStepType::Turn,
            "UTurn" => RoutePedestrianTravelStepType::UTurn,
            other => RoutePedestrianTravelStepType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for RoutePedestrianTravelStepType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(RoutePedestrianTravelStepType::from(s))
    }
}
impl RoutePedestrianTravelStepType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            RoutePedestrianTravelStepType::Arrive => "Arrive",
            RoutePedestrianTravelStepType::Continue => "Continue",
            RoutePedestrianTravelStepType::Depart => "Depart",
            RoutePedestrianTravelStepType::Exit => "Exit",
            RoutePedestrianTravelStepType::Keep => "Keep",
            RoutePedestrianTravelStepType::Ramp => "Ramp",
            RoutePedestrianTravelStepType::RoundaboutEnter => "RoundaboutEnter",
            RoutePedestrianTravelStepType::RoundaboutExit => "RoundaboutExit",
            RoutePedestrianTravelStepType::RoundaboutPass => "RoundaboutPass",
            RoutePedestrianTravelStepType::Turn => "Turn",
            RoutePedestrianTravelStepType::UTurn => "UTurn",
            RoutePedestrianTravelStepType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "Arrive",
            "Continue",
            "Depart",
            "Exit",
            "Keep",
            "Ramp",
            "RoundaboutEnter",
            "RoundaboutExit",
            "RoundaboutPass",
            "Turn",
            "UTurn",
        ]
    }
}
impl ::std::convert::AsRef<str> for RoutePedestrianTravelStepType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl RoutePedestrianTravelStepType {
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
impl ::std::fmt::Display for RoutePedestrianTravelStepType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            RoutePedestrianTravelStepType::Arrive => write!(f, "Arrive"),
            RoutePedestrianTravelStepType::Continue => write!(f, "Continue"),
            RoutePedestrianTravelStepType::Depart => write!(f, "Depart"),
            RoutePedestrianTravelStepType::Exit => write!(f, "Exit"),
            RoutePedestrianTravelStepType::Keep => write!(f, "Keep"),
            RoutePedestrianTravelStepType::Ramp => write!(f, "Ramp"),
            RoutePedestrianTravelStepType::RoundaboutEnter => write!(f, "RoundaboutEnter"),
            RoutePedestrianTravelStepType::RoundaboutExit => write!(f, "RoundaboutExit"),
            RoutePedestrianTravelStepType::RoundaboutPass => write!(f, "RoundaboutPass"),
            RoutePedestrianTravelStepType::Turn => write!(f, "Turn"),
            RoutePedestrianTravelStepType::UTurn => write!(f, "UTurn"),
            RoutePedestrianTravelStepType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
