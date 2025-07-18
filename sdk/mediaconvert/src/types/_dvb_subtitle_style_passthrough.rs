// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `DvbSubtitleStylePassthrough`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let dvbsubtitlestylepassthrough = unimplemented!();
/// match dvbsubtitlestylepassthrough {
///     DvbSubtitleStylePassthrough::Disabled => { /* ... */ },
///     DvbSubtitleStylePassthrough::Enabled => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `dvbsubtitlestylepassthrough` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `DvbSubtitleStylePassthrough::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `DvbSubtitleStylePassthrough::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `DvbSubtitleStylePassthrough::NewFeature` is defined.
/// Specifically, when `dvbsubtitlestylepassthrough` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `DvbSubtitleStylePassthrough::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// To use the available style, color, and position information from your input captions: Set Style passthrough to Enabled. Note that MediaConvert uses default settings for any missing style or position information in your input captions To ignore the style and position information from your input captions and use default settings: Leave blank or keep the default value, Disabled. Default settings include white text with black outlining, bottom-center positioning, and automatic sizing. Whether you set Style passthrough to enabled or not, you can also choose to manually override any of the individual style and position settings. You can also override any fonts by manually specifying custom font files.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum DvbSubtitleStylePassthrough {
    #[allow(missing_docs)] // documentation missing in model
    Disabled,
    #[allow(missing_docs)] // documentation missing in model
    Enabled,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for DvbSubtitleStylePassthrough {
    fn from(s: &str) -> Self {
        match s {
            "DISABLED" => DvbSubtitleStylePassthrough::Disabled,
            "ENABLED" => DvbSubtitleStylePassthrough::Enabled,
            other => DvbSubtitleStylePassthrough::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for DvbSubtitleStylePassthrough {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(DvbSubtitleStylePassthrough::from(s))
    }
}
impl DvbSubtitleStylePassthrough {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            DvbSubtitleStylePassthrough::Disabled => "DISABLED",
            DvbSubtitleStylePassthrough::Enabled => "ENABLED",
            DvbSubtitleStylePassthrough::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["DISABLED", "ENABLED"]
    }
}
impl ::std::convert::AsRef<str> for DvbSubtitleStylePassthrough {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl DvbSubtitleStylePassthrough {
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
impl ::std::fmt::Display for DvbSubtitleStylePassthrough {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            DvbSubtitleStylePassthrough::Disabled => write!(f, "DISABLED"),
            DvbSubtitleStylePassthrough::Enabled => write!(f, "ENABLED"),
            DvbSubtitleStylePassthrough::Unknown(value) => write!(f, "{}", value),
        }
    }
}
