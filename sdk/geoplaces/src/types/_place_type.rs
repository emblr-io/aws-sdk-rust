// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `PlaceType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let placetype = unimplemented!();
/// match placetype {
///     PlaceType::Block => { /* ... */ },
///     PlaceType::Country => { /* ... */ },
///     PlaceType::District => { /* ... */ },
///     PlaceType::InterpolatedAddress => { /* ... */ },
///     PlaceType::Intersection => { /* ... */ },
///     PlaceType::Locality => { /* ... */ },
///     PlaceType::PointAddress => { /* ... */ },
///     PlaceType::PointOfInterest => { /* ... */ },
///     PlaceType::PostalCode => { /* ... */ },
///     PlaceType::Region => { /* ... */ },
///     PlaceType::SecondaryAddress => { /* ... */ },
///     PlaceType::Street => { /* ... */ },
///     PlaceType::SubBlock => { /* ... */ },
///     PlaceType::SubDistrict => { /* ... */ },
///     PlaceType::SubRegion => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `placetype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `PlaceType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `PlaceType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `PlaceType::NewFeature` is defined.
/// Specifically, when `placetype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `PlaceType::NewFeature` also yielding `"NewFeature"`.
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
#[derive(::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::hash::Hash)]
pub enum PlaceType {
    #[allow(missing_docs)] // documentation missing in model
    Block,
    #[allow(missing_docs)] // documentation missing in model
    Country,
    #[allow(missing_docs)] // documentation missing in model
    District,
    #[allow(missing_docs)] // documentation missing in model
    InterpolatedAddress,
    #[allow(missing_docs)] // documentation missing in model
    Intersection,
    #[allow(missing_docs)] // documentation missing in model
    Locality,
    #[allow(missing_docs)] // documentation missing in model
    PointAddress,
    #[allow(missing_docs)] // documentation missing in model
    PointOfInterest,
    #[allow(missing_docs)] // documentation missing in model
    PostalCode,
    #[allow(missing_docs)] // documentation missing in model
    Region,
    #[allow(missing_docs)] // documentation missing in model
    SecondaryAddress,
    #[allow(missing_docs)] // documentation missing in model
    Street,
    #[allow(missing_docs)] // documentation missing in model
    SubBlock,
    #[allow(missing_docs)] // documentation missing in model
    SubDistrict,
    #[allow(missing_docs)] // documentation missing in model
    SubRegion,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for PlaceType {
    fn from(s: &str) -> Self {
        match s {
            "Block" => PlaceType::Block,
            "Country" => PlaceType::Country,
            "District" => PlaceType::District,
            "InterpolatedAddress" => PlaceType::InterpolatedAddress,
            "Intersection" => PlaceType::Intersection,
            "Locality" => PlaceType::Locality,
            "PointAddress" => PlaceType::PointAddress,
            "PointOfInterest" => PlaceType::PointOfInterest,
            "PostalCode" => PlaceType::PostalCode,
            "Region" => PlaceType::Region,
            "SecondaryAddress" => PlaceType::SecondaryAddress,
            "Street" => PlaceType::Street,
            "SubBlock" => PlaceType::SubBlock,
            "SubDistrict" => PlaceType::SubDistrict,
            "SubRegion" => PlaceType::SubRegion,
            other => PlaceType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for PlaceType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(PlaceType::from(s))
    }
}
impl PlaceType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            PlaceType::Block => "Block",
            PlaceType::Country => "Country",
            PlaceType::District => "District",
            PlaceType::InterpolatedAddress => "InterpolatedAddress",
            PlaceType::Intersection => "Intersection",
            PlaceType::Locality => "Locality",
            PlaceType::PointAddress => "PointAddress",
            PlaceType::PointOfInterest => "PointOfInterest",
            PlaceType::PostalCode => "PostalCode",
            PlaceType::Region => "Region",
            PlaceType::SecondaryAddress => "SecondaryAddress",
            PlaceType::Street => "Street",
            PlaceType::SubBlock => "SubBlock",
            PlaceType::SubDistrict => "SubDistrict",
            PlaceType::SubRegion => "SubRegion",
            PlaceType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "Block",
            "Country",
            "District",
            "InterpolatedAddress",
            "Intersection",
            "Locality",
            "PointAddress",
            "PointOfInterest",
            "PostalCode",
            "Region",
            "SecondaryAddress",
            "Street",
            "SubBlock",
            "SubDistrict",
            "SubRegion",
        ]
    }
}
impl ::std::convert::AsRef<str> for PlaceType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl PlaceType {
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
impl ::std::fmt::Display for PlaceType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PlaceType::Block => write!(f, "Block"),
            PlaceType::Country => write!(f, "Country"),
            PlaceType::District => write!(f, "District"),
            PlaceType::InterpolatedAddress => write!(f, "InterpolatedAddress"),
            PlaceType::Intersection => write!(f, "Intersection"),
            PlaceType::Locality => write!(f, "Locality"),
            PlaceType::PointAddress => write!(f, "PointAddress"),
            PlaceType::PointOfInterest => write!(f, "PointOfInterest"),
            PlaceType::PostalCode => write!(f, "PostalCode"),
            PlaceType::Region => write!(f, "Region"),
            PlaceType::SecondaryAddress => write!(f, "SecondaryAddress"),
            PlaceType::Street => write!(f, "Street"),
            PlaceType::SubBlock => write!(f, "SubBlock"),
            PlaceType::SubDistrict => write!(f, "SubDistrict"),
            PlaceType::SubRegion => write!(f, "SubRegion"),
            PlaceType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
impl ::std::fmt::Debug for PlaceType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::std::write!(f, "*** Sensitive Data Redacted ***")
    }
}
