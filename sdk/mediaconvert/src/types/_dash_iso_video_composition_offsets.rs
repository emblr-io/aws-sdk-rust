// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `DashIsoVideoCompositionOffsets`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let dashisovideocompositionoffsets = unimplemented!();
/// match dashisovideocompositionoffsets {
///     DashIsoVideoCompositionOffsets::Signed => { /* ... */ },
///     DashIsoVideoCompositionOffsets::Unsigned => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `dashisovideocompositionoffsets` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `DashIsoVideoCompositionOffsets::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `DashIsoVideoCompositionOffsets::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `DashIsoVideoCompositionOffsets::NewFeature` is defined.
/// Specifically, when `dashisovideocompositionoffsets` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `DashIsoVideoCompositionOffsets::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Specify the video sample composition time offset mode in the output fMP4 TRUN box. For wider player compatibility, set Video composition offsets to Unsigned or leave blank. The earliest presentation time may be greater than zero, and sample composition time offsets will increment using unsigned integers. For strict fMP4 video and audio timing, set Video composition offsets to Signed. The earliest presentation time will be equal to zero, and sample composition time offsets will increment using signed integers.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum DashIsoVideoCompositionOffsets {
    #[allow(missing_docs)] // documentation missing in model
    Signed,
    #[allow(missing_docs)] // documentation missing in model
    Unsigned,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for DashIsoVideoCompositionOffsets {
    fn from(s: &str) -> Self {
        match s {
            "SIGNED" => DashIsoVideoCompositionOffsets::Signed,
            "UNSIGNED" => DashIsoVideoCompositionOffsets::Unsigned,
            other => DashIsoVideoCompositionOffsets::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for DashIsoVideoCompositionOffsets {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(DashIsoVideoCompositionOffsets::from(s))
    }
}
impl DashIsoVideoCompositionOffsets {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            DashIsoVideoCompositionOffsets::Signed => "SIGNED",
            DashIsoVideoCompositionOffsets::Unsigned => "UNSIGNED",
            DashIsoVideoCompositionOffsets::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["SIGNED", "UNSIGNED"]
    }
}
impl ::std::convert::AsRef<str> for DashIsoVideoCompositionOffsets {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl DashIsoVideoCompositionOffsets {
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
impl ::std::fmt::Display for DashIsoVideoCompositionOffsets {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            DashIsoVideoCompositionOffsets::Signed => write!(f, "SIGNED"),
            DashIsoVideoCompositionOffsets::Unsigned => write!(f, "UNSIGNED"),
            DashIsoVideoCompositionOffsets::Unknown(value) => write!(f, "{}", value),
        }
    }
}
