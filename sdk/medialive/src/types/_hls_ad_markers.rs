// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `HlsAdMarkers`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let hlsadmarkers = unimplemented!();
/// match hlsadmarkers {
///     HlsAdMarkers::Adobe => { /* ... */ },
///     HlsAdMarkers::Elemental => { /* ... */ },
///     HlsAdMarkers::ElementalScte35 => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `hlsadmarkers` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `HlsAdMarkers::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `HlsAdMarkers::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `HlsAdMarkers::NewFeature` is defined.
/// Specifically, when `hlsadmarkers` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `HlsAdMarkers::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Hls Ad Markers
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum HlsAdMarkers {
    #[allow(missing_docs)] // documentation missing in model
    Adobe,
    #[allow(missing_docs)] // documentation missing in model
    Elemental,
    #[allow(missing_docs)] // documentation missing in model
    ElementalScte35,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for HlsAdMarkers {
    fn from(s: &str) -> Self {
        match s {
            "ADOBE" => HlsAdMarkers::Adobe,
            "ELEMENTAL" => HlsAdMarkers::Elemental,
            "ELEMENTAL_SCTE35" => HlsAdMarkers::ElementalScte35,
            other => HlsAdMarkers::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for HlsAdMarkers {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(HlsAdMarkers::from(s))
    }
}
impl HlsAdMarkers {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            HlsAdMarkers::Adobe => "ADOBE",
            HlsAdMarkers::Elemental => "ELEMENTAL",
            HlsAdMarkers::ElementalScte35 => "ELEMENTAL_SCTE35",
            HlsAdMarkers::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["ADOBE", "ELEMENTAL", "ELEMENTAL_SCTE35"]
    }
}
impl ::std::convert::AsRef<str> for HlsAdMarkers {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl HlsAdMarkers {
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
impl ::std::fmt::Display for HlsAdMarkers {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            HlsAdMarkers::Adobe => write!(f, "ADOBE"),
            HlsAdMarkers::Elemental => write!(f, "ELEMENTAL"),
            HlsAdMarkers::ElementalScte35 => write!(f, "ELEMENTAL_SCTE35"),
            HlsAdMarkers::Unknown(value) => write!(f, "{}", value),
        }
    }
}
