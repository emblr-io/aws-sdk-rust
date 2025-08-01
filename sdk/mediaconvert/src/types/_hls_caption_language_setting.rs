// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `HlsCaptionLanguageSetting`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let hlscaptionlanguagesetting = unimplemented!();
/// match hlscaptionlanguagesetting {
///     HlsCaptionLanguageSetting::Insert => { /* ... */ },
///     HlsCaptionLanguageSetting::None => { /* ... */ },
///     HlsCaptionLanguageSetting::Omit => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `hlscaptionlanguagesetting` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `HlsCaptionLanguageSetting::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `HlsCaptionLanguageSetting::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `HlsCaptionLanguageSetting::NewFeature` is defined.
/// Specifically, when `hlscaptionlanguagesetting` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `HlsCaptionLanguageSetting::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Applies only to 608 Embedded output captions. Insert: Include CLOSED-CAPTIONS lines in the manifest. Specify at least one language in the CC1 Language Code field. One CLOSED-CAPTION line is added for each Language Code you specify. Make sure to specify the languages in the order in which they appear in the original source (if the source is embedded format) or the order of the caption selectors (if the source is other than embedded). Otherwise, languages in the manifest will not match up properly with the output captions. None: Include CLOSED-CAPTIONS=NONE line in the manifest. Omit: Omit any CLOSED-CAPTIONS line from the manifest.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum HlsCaptionLanguageSetting {
    #[allow(missing_docs)] // documentation missing in model
    Insert,
    #[allow(missing_docs)] // documentation missing in model
    None,
    #[allow(missing_docs)] // documentation missing in model
    Omit,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for HlsCaptionLanguageSetting {
    fn from(s: &str) -> Self {
        match s {
            "INSERT" => HlsCaptionLanguageSetting::Insert,
            "NONE" => HlsCaptionLanguageSetting::None,
            "OMIT" => HlsCaptionLanguageSetting::Omit,
            other => HlsCaptionLanguageSetting::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for HlsCaptionLanguageSetting {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(HlsCaptionLanguageSetting::from(s))
    }
}
impl HlsCaptionLanguageSetting {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            HlsCaptionLanguageSetting::Insert => "INSERT",
            HlsCaptionLanguageSetting::None => "NONE",
            HlsCaptionLanguageSetting::Omit => "OMIT",
            HlsCaptionLanguageSetting::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["INSERT", "NONE", "OMIT"]
    }
}
impl ::std::convert::AsRef<str> for HlsCaptionLanguageSetting {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl HlsCaptionLanguageSetting {
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
impl ::std::fmt::Display for HlsCaptionLanguageSetting {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            HlsCaptionLanguageSetting::Insert => write!(f, "INSERT"),
            HlsCaptionLanguageSetting::None => write!(f, "NONE"),
            HlsCaptionLanguageSetting::Omit => write!(f, "OMIT"),
            HlsCaptionLanguageSetting::Unknown(value) => write!(f, "{}", value),
        }
    }
}
