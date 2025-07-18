// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `Vc3ScanTypeConversionMode`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let vc3scantypeconversionmode = unimplemented!();
/// match vc3scantypeconversionmode {
///     Vc3ScanTypeConversionMode::Interlaced => { /* ... */ },
///     Vc3ScanTypeConversionMode::InterlacedOptimize => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `vc3scantypeconversionmode` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `Vc3ScanTypeConversionMode::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `Vc3ScanTypeConversionMode::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `Vc3ScanTypeConversionMode::NewFeature` is defined.
/// Specifically, when `vc3scantypeconversionmode` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `Vc3ScanTypeConversionMode::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Use this setting for interlaced outputs, when your output frame rate is half of your input frame rate. In this situation, choose Optimized interlacing to create a better quality interlaced output. In this case, each progressive frame from the input corresponds to an interlaced field in the output. Keep the default value, Basic interlacing, for all other output frame rates. With basic interlacing, MediaConvert performs any frame rate conversion first and then interlaces the frames. When you choose Optimized interlacing and you set your output frame rate to a value that isn't suitable for optimized interlacing, MediaConvert automatically falls back to basic interlacing. Required settings: To use optimized interlacing, you must set Telecine to None or Soft. You can't use optimized interlacing for hard telecine outputs. You must also set Interlace mode to a value other than Progressive.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum Vc3ScanTypeConversionMode {
    #[allow(missing_docs)] // documentation missing in model
    Interlaced,
    #[allow(missing_docs)] // documentation missing in model
    InterlacedOptimize,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for Vc3ScanTypeConversionMode {
    fn from(s: &str) -> Self {
        match s {
            "INTERLACED" => Vc3ScanTypeConversionMode::Interlaced,
            "INTERLACED_OPTIMIZE" => Vc3ScanTypeConversionMode::InterlacedOptimize,
            other => Vc3ScanTypeConversionMode::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for Vc3ScanTypeConversionMode {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(Vc3ScanTypeConversionMode::from(s))
    }
}
impl Vc3ScanTypeConversionMode {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            Vc3ScanTypeConversionMode::Interlaced => "INTERLACED",
            Vc3ScanTypeConversionMode::InterlacedOptimize => "INTERLACED_OPTIMIZE",
            Vc3ScanTypeConversionMode::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["INTERLACED", "INTERLACED_OPTIMIZE"]
    }
}
impl ::std::convert::AsRef<str> for Vc3ScanTypeConversionMode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Vc3ScanTypeConversionMode {
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
impl ::std::fmt::Display for Vc3ScanTypeConversionMode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Vc3ScanTypeConversionMode::Interlaced => write!(f, "INTERLACED"),
            Vc3ScanTypeConversionMode::InterlacedOptimize => write!(f, "INTERLACED_OPTIMIZE"),
            Vc3ScanTypeConversionMode::Unknown(value) => write!(f, "{}", value),
        }
    }
}
