// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `DolbyVisionMapping`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let dolbyvisionmapping = unimplemented!();
/// match dolbyvisionmapping {
///     DolbyVisionMapping::Hdr101000 => { /* ... */ },
///     DolbyVisionMapping::Hdr10Nomap => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `dolbyvisionmapping` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `DolbyVisionMapping::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `DolbyVisionMapping::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `DolbyVisionMapping::NewFeature` is defined.
/// Specifically, when `dolbyvisionmapping` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `DolbyVisionMapping::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Required when you set Dolby Vision Profile to Profile 8.1. When you set Content mapping to None, content mapping is not applied to the HDR10-compatible signal. Depending on the source peak nit level, clipping might occur on HDR devices without Dolby Vision. When you set Content mapping to HDR10 1000, the transcoder creates a 1,000 nits peak HDR10-compatible signal by applying static content mapping to the source. This mode is speed-optimized for PQ10 sources with metadata that is created from analysis. For graded Dolby Vision content, be aware that creative intent might not be guaranteed with extreme 1,000 nits trims.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum DolbyVisionMapping {
    #[allow(missing_docs)] // documentation missing in model
    Hdr101000,
    #[allow(missing_docs)] // documentation missing in model
    Hdr10Nomap,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for DolbyVisionMapping {
    fn from(s: &str) -> Self {
        match s {
            "HDR10_1000" => DolbyVisionMapping::Hdr101000,
            "HDR10_NOMAP" => DolbyVisionMapping::Hdr10Nomap,
            other => DolbyVisionMapping::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for DolbyVisionMapping {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(DolbyVisionMapping::from(s))
    }
}
impl DolbyVisionMapping {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            DolbyVisionMapping::Hdr101000 => "HDR10_1000",
            DolbyVisionMapping::Hdr10Nomap => "HDR10_NOMAP",
            DolbyVisionMapping::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["HDR10_1000", "HDR10_NOMAP"]
    }
}
impl ::std::convert::AsRef<str> for DolbyVisionMapping {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl DolbyVisionMapping {
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
impl ::std::fmt::Display for DolbyVisionMapping {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            DolbyVisionMapping::Hdr101000 => write!(f, "HDR10_1000"),
            DolbyVisionMapping::Hdr10Nomap => write!(f, "HDR10_NOMAP"),
            DolbyVisionMapping::Unknown(value) => write!(f, "{}", value),
        }
    }
}
