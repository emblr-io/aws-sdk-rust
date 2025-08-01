// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `M2tsSegmentationStyle`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let m2tssegmentationstyle = unimplemented!();
/// match m2tssegmentationstyle {
///     M2tsSegmentationStyle::MaintainCadence => { /* ... */ },
///     M2tsSegmentationStyle::ResetCadence => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `m2tssegmentationstyle` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `M2tsSegmentationStyle::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `M2tsSegmentationStyle::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `M2tsSegmentationStyle::NewFeature` is defined.
/// Specifically, when `m2tssegmentationstyle` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `M2tsSegmentationStyle::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// The segmentation style parameter controls how segmentation markers are inserted into the transport stream. With avails, it is possible that segments may be truncated, which can influence where future segmentation markers are inserted. When a segmentation style of "reset_cadence" is selected and a segment is truncated due to an avail, we will reset the segmentation cadence. This means the subsequent segment will have a duration of of $segmentation_time seconds. When a segmentation style of "maintain_cadence" is selected and a segment is truncated due to an avail, we will not reset the segmentation cadence. This means the subsequent segment will likely be truncated as well. However, all segments after that will have a duration of $segmentation_time seconds. Note that EBP lookahead is a slight exception to this rule.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum M2tsSegmentationStyle {
    #[allow(missing_docs)] // documentation missing in model
    MaintainCadence,
    #[allow(missing_docs)] // documentation missing in model
    ResetCadence,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for M2tsSegmentationStyle {
    fn from(s: &str) -> Self {
        match s {
            "MAINTAIN_CADENCE" => M2tsSegmentationStyle::MaintainCadence,
            "RESET_CADENCE" => M2tsSegmentationStyle::ResetCadence,
            other => M2tsSegmentationStyle::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for M2tsSegmentationStyle {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(M2tsSegmentationStyle::from(s))
    }
}
impl M2tsSegmentationStyle {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            M2tsSegmentationStyle::MaintainCadence => "MAINTAIN_CADENCE",
            M2tsSegmentationStyle::ResetCadence => "RESET_CADENCE",
            M2tsSegmentationStyle::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["MAINTAIN_CADENCE", "RESET_CADENCE"]
    }
}
impl ::std::convert::AsRef<str> for M2tsSegmentationStyle {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl M2tsSegmentationStyle {
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
impl ::std::fmt::Display for M2tsSegmentationStyle {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            M2tsSegmentationStyle::MaintainCadence => write!(f, "MAINTAIN_CADENCE"),
            M2tsSegmentationStyle::ResetCadence => write!(f, "RESET_CADENCE"),
            M2tsSegmentationStyle::Unknown(value) => write!(f, "{}", value),
        }
    }
}
