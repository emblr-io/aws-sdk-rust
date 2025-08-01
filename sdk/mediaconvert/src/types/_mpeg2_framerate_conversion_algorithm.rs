// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `Mpeg2FramerateConversionAlgorithm`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let mpeg2framerateconversionalgorithm = unimplemented!();
/// match mpeg2framerateconversionalgorithm {
///     Mpeg2FramerateConversionAlgorithm::DuplicateDrop => { /* ... */ },
///     Mpeg2FramerateConversionAlgorithm::Frameformer => { /* ... */ },
///     Mpeg2FramerateConversionAlgorithm::Interpolate => { /* ... */ },
///     Mpeg2FramerateConversionAlgorithm::MaintainFrameCount => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `mpeg2framerateconversionalgorithm` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `Mpeg2FramerateConversionAlgorithm::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `Mpeg2FramerateConversionAlgorithm::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `Mpeg2FramerateConversionAlgorithm::NewFeature` is defined.
/// Specifically, when `mpeg2framerateconversionalgorithm` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `Mpeg2FramerateConversionAlgorithm::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Choose the method that you want MediaConvert to use when increasing or decreasing your video's frame rate. For numerically simple conversions, such as 60 fps to 30 fps: We recommend that you keep the default value, Drop duplicate. For numerically complex conversions, to avoid stutter: Choose Interpolate. This results in a smooth picture, but might introduce undesirable video artifacts. For complex frame rate conversions, especially if your source video has already been converted from its original cadence: Choose FrameFormer to do motion-compensated interpolation. FrameFormer uses the best conversion method frame by frame. Note that using FrameFormer increases the transcoding time and incurs a significant add-on cost. When you choose FrameFormer, your input video resolution must be at least 128x96. To create an output with the same number of frames as your input: Choose Maintain frame count. When you do, MediaConvert will not drop, interpolate, add, or otherwise change the frame count from your input to your output. Note that since the frame count is maintained, the duration of your output will become shorter at higher frame rates and longer at lower frame rates.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum Mpeg2FramerateConversionAlgorithm {
    #[allow(missing_docs)] // documentation missing in model
    DuplicateDrop,
    #[allow(missing_docs)] // documentation missing in model
    Frameformer,
    #[allow(missing_docs)] // documentation missing in model
    Interpolate,
    #[allow(missing_docs)] // documentation missing in model
    MaintainFrameCount,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for Mpeg2FramerateConversionAlgorithm {
    fn from(s: &str) -> Self {
        match s {
            "DUPLICATE_DROP" => Mpeg2FramerateConversionAlgorithm::DuplicateDrop,
            "FRAMEFORMER" => Mpeg2FramerateConversionAlgorithm::Frameformer,
            "INTERPOLATE" => Mpeg2FramerateConversionAlgorithm::Interpolate,
            "MAINTAIN_FRAME_COUNT" => Mpeg2FramerateConversionAlgorithm::MaintainFrameCount,
            other => Mpeg2FramerateConversionAlgorithm::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for Mpeg2FramerateConversionAlgorithm {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(Mpeg2FramerateConversionAlgorithm::from(s))
    }
}
impl Mpeg2FramerateConversionAlgorithm {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            Mpeg2FramerateConversionAlgorithm::DuplicateDrop => "DUPLICATE_DROP",
            Mpeg2FramerateConversionAlgorithm::Frameformer => "FRAMEFORMER",
            Mpeg2FramerateConversionAlgorithm::Interpolate => "INTERPOLATE",
            Mpeg2FramerateConversionAlgorithm::MaintainFrameCount => "MAINTAIN_FRAME_COUNT",
            Mpeg2FramerateConversionAlgorithm::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["DUPLICATE_DROP", "FRAMEFORMER", "INTERPOLATE", "MAINTAIN_FRAME_COUNT"]
    }
}
impl ::std::convert::AsRef<str> for Mpeg2FramerateConversionAlgorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Mpeg2FramerateConversionAlgorithm {
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
impl ::std::fmt::Display for Mpeg2FramerateConversionAlgorithm {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Mpeg2FramerateConversionAlgorithm::DuplicateDrop => write!(f, "DUPLICATE_DROP"),
            Mpeg2FramerateConversionAlgorithm::Frameformer => write!(f, "FRAMEFORMER"),
            Mpeg2FramerateConversionAlgorithm::Interpolate => write!(f, "INTERPOLATE"),
            Mpeg2FramerateConversionAlgorithm::MaintainFrameCount => write!(f, "MAINTAIN_FRAME_COUNT"),
            Mpeg2FramerateConversionAlgorithm::Unknown(value) => write!(f, "{}", value),
        }
    }
}
