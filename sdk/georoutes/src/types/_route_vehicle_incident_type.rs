// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `RouteVehicleIncidentType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let routevehicleincidenttype = unimplemented!();
/// match routevehicleincidenttype {
///     RouteVehicleIncidentType::Accident => { /* ... */ },
///     RouteVehicleIncidentType::Congestion => { /* ... */ },
///     RouteVehicleIncidentType::Construction => { /* ... */ },
///     RouteVehicleIncidentType::DisabledVehicle => { /* ... */ },
///     RouteVehicleIncidentType::LaneRestriction => { /* ... */ },
///     RouteVehicleIncidentType::MassTransit => { /* ... */ },
///     RouteVehicleIncidentType::Other => { /* ... */ },
///     RouteVehicleIncidentType::PlannedEvent => { /* ... */ },
///     RouteVehicleIncidentType::RoadClosure => { /* ... */ },
///     RouteVehicleIncidentType::RoadHazard => { /* ... */ },
///     RouteVehicleIncidentType::Weather => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `routevehicleincidenttype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `RouteVehicleIncidentType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `RouteVehicleIncidentType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `RouteVehicleIncidentType::NewFeature` is defined.
/// Specifically, when `routevehicleincidenttype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `RouteVehicleIncidentType::NewFeature` also yielding `"NewFeature"`.
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
pub enum RouteVehicleIncidentType {
    #[allow(missing_docs)] // documentation missing in model
    Accident,
    #[allow(missing_docs)] // documentation missing in model
    Congestion,
    #[allow(missing_docs)] // documentation missing in model
    Construction,
    #[allow(missing_docs)] // documentation missing in model
    DisabledVehicle,
    #[allow(missing_docs)] // documentation missing in model
    LaneRestriction,
    #[allow(missing_docs)] // documentation missing in model
    MassTransit,
    #[allow(missing_docs)] // documentation missing in model
    Other,
    #[allow(missing_docs)] // documentation missing in model
    PlannedEvent,
    #[allow(missing_docs)] // documentation missing in model
    RoadClosure,
    #[allow(missing_docs)] // documentation missing in model
    RoadHazard,
    #[allow(missing_docs)] // documentation missing in model
    Weather,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for RouteVehicleIncidentType {
    fn from(s: &str) -> Self {
        match s {
            "Accident" => RouteVehicleIncidentType::Accident,
            "Congestion" => RouteVehicleIncidentType::Congestion,
            "Construction" => RouteVehicleIncidentType::Construction,
            "DisabledVehicle" => RouteVehicleIncidentType::DisabledVehicle,
            "LaneRestriction" => RouteVehicleIncidentType::LaneRestriction,
            "MassTransit" => RouteVehicleIncidentType::MassTransit,
            "Other" => RouteVehicleIncidentType::Other,
            "PlannedEvent" => RouteVehicleIncidentType::PlannedEvent,
            "RoadClosure" => RouteVehicleIncidentType::RoadClosure,
            "RoadHazard" => RouteVehicleIncidentType::RoadHazard,
            "Weather" => RouteVehicleIncidentType::Weather,
            other => RouteVehicleIncidentType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for RouteVehicleIncidentType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(RouteVehicleIncidentType::from(s))
    }
}
impl RouteVehicleIncidentType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            RouteVehicleIncidentType::Accident => "Accident",
            RouteVehicleIncidentType::Congestion => "Congestion",
            RouteVehicleIncidentType::Construction => "Construction",
            RouteVehicleIncidentType::DisabledVehicle => "DisabledVehicle",
            RouteVehicleIncidentType::LaneRestriction => "LaneRestriction",
            RouteVehicleIncidentType::MassTransit => "MassTransit",
            RouteVehicleIncidentType::Other => "Other",
            RouteVehicleIncidentType::PlannedEvent => "PlannedEvent",
            RouteVehicleIncidentType::RoadClosure => "RoadClosure",
            RouteVehicleIncidentType::RoadHazard => "RoadHazard",
            RouteVehicleIncidentType::Weather => "Weather",
            RouteVehicleIncidentType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "Accident",
            "Congestion",
            "Construction",
            "DisabledVehicle",
            "LaneRestriction",
            "MassTransit",
            "Other",
            "PlannedEvent",
            "RoadClosure",
            "RoadHazard",
            "Weather",
        ]
    }
}
impl ::std::convert::AsRef<str> for RouteVehicleIncidentType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl RouteVehicleIncidentType {
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
impl ::std::fmt::Display for RouteVehicleIncidentType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            RouteVehicleIncidentType::Accident => write!(f, "Accident"),
            RouteVehicleIncidentType::Congestion => write!(f, "Congestion"),
            RouteVehicleIncidentType::Construction => write!(f, "Construction"),
            RouteVehicleIncidentType::DisabledVehicle => write!(f, "DisabledVehicle"),
            RouteVehicleIncidentType::LaneRestriction => write!(f, "LaneRestriction"),
            RouteVehicleIncidentType::MassTransit => write!(f, "MassTransit"),
            RouteVehicleIncidentType::Other => write!(f, "Other"),
            RouteVehicleIncidentType::PlannedEvent => write!(f, "PlannedEvent"),
            RouteVehicleIncidentType::RoadClosure => write!(f, "RoadClosure"),
            RouteVehicleIncidentType::RoadHazard => write!(f, "RoadHazard"),
            RouteVehicleIncidentType::Weather => write!(f, "Weather"),
            RouteVehicleIncidentType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
