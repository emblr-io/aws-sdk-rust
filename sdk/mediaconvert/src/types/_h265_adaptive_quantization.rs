// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `H265AdaptiveQuantization`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let h265adaptivequantization = unimplemented!();
/// match h265adaptivequantization {
///     H265AdaptiveQuantization::Auto => { /* ... */ },
///     H265AdaptiveQuantization::High => { /* ... */ },
///     H265AdaptiveQuantization::Higher => { /* ... */ },
///     H265AdaptiveQuantization::Low => { /* ... */ },
///     H265AdaptiveQuantization::Max => { /* ... */ },
///     H265AdaptiveQuantization::Medium => { /* ... */ },
///     H265AdaptiveQuantization::Off => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `h265adaptivequantization` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `H265AdaptiveQuantization::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `H265AdaptiveQuantization::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `H265AdaptiveQuantization::NewFeature` is defined.
/// Specifically, when `h265adaptivequantization` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `H265AdaptiveQuantization::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// When you set Adaptive Quantization to Auto, or leave blank, MediaConvert automatically applies quantization to improve the video quality of your output. Set Adaptive Quantization to Low, Medium, High, Higher, or Max to manually control the strength of the quantization filter. When you do, you can specify a value for Spatial Adaptive Quantization, Temporal Adaptive Quantization, and Flicker Adaptive Quantization, to further control the quantization filter. Set Adaptive Quantization to Off to apply no quantization to your output.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum H265AdaptiveQuantization {
    #[allow(missing_docs)] // documentation missing in model
    Auto,
    #[allow(missing_docs)] // documentation missing in model
    High,
    #[allow(missing_docs)] // documentation missing in model
    Higher,
    #[allow(missing_docs)] // documentation missing in model
    Low,
    #[allow(missing_docs)] // documentation missing in model
    Max,
    #[allow(missing_docs)] // documentation missing in model
    Medium,
    #[allow(missing_docs)] // documentation missing in model
    Off,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for H265AdaptiveQuantization {
    fn from(s: &str) -> Self {
        match s {
            "AUTO" => H265AdaptiveQuantization::Auto,
            "HIGH" => H265AdaptiveQuantization::High,
            "HIGHER" => H265AdaptiveQuantization::Higher,
            "LOW" => H265AdaptiveQuantization::Low,
            "MAX" => H265AdaptiveQuantization::Max,
            "MEDIUM" => H265AdaptiveQuantization::Medium,
            "OFF" => H265AdaptiveQuantization::Off,
            other => H265AdaptiveQuantization::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for H265AdaptiveQuantization {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(H265AdaptiveQuantization::from(s))
    }
}
impl H265AdaptiveQuantization {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            H265AdaptiveQuantization::Auto => "AUTO",
            H265AdaptiveQuantization::High => "HIGH",
            H265AdaptiveQuantization::Higher => "HIGHER",
            H265AdaptiveQuantization::Low => "LOW",
            H265AdaptiveQuantization::Max => "MAX",
            H265AdaptiveQuantization::Medium => "MEDIUM",
            H265AdaptiveQuantization::Off => "OFF",
            H265AdaptiveQuantization::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["AUTO", "HIGH", "HIGHER", "LOW", "MAX", "MEDIUM", "OFF"]
    }
}
impl ::std::convert::AsRef<str> for H265AdaptiveQuantization {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl H265AdaptiveQuantization {
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
impl ::std::fmt::Display for H265AdaptiveQuantization {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            H265AdaptiveQuantization::Auto => write!(f, "AUTO"),
            H265AdaptiveQuantization::High => write!(f, "HIGH"),
            H265AdaptiveQuantization::Higher => write!(f, "HIGHER"),
            H265AdaptiveQuantization::Low => write!(f, "LOW"),
            H265AdaptiveQuantization::Max => write!(f, "MAX"),
            H265AdaptiveQuantization::Medium => write!(f, "MEDIUM"),
            H265AdaptiveQuantization::Off => write!(f, "OFF"),
            H265AdaptiveQuantization::Unknown(value) => write!(f, "{}", value),
        }
    }
}
