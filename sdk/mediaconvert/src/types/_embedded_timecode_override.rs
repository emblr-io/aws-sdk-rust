// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `EmbeddedTimecodeOverride`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let embeddedtimecodeoverride = unimplemented!();
/// match embeddedtimecodeoverride {
///     EmbeddedTimecodeOverride::None => { /* ... */ },
///     EmbeddedTimecodeOverride::UseMdpm => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `embeddedtimecodeoverride` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `EmbeddedTimecodeOverride::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `EmbeddedTimecodeOverride::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `EmbeddedTimecodeOverride::NewFeature` is defined.
/// Specifically, when `embeddedtimecodeoverride` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `EmbeddedTimecodeOverride::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Set Embedded timecode override to Use MDPM when your AVCHD input contains timecode tag data in the Modified Digital Video Pack Metadata. When you do, we recommend you also set Timecode source to Embedded. Leave Embedded timecode override blank, or set to None, when your input does not contain MDPM timecode.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum EmbeddedTimecodeOverride {
    #[allow(missing_docs)] // documentation missing in model
    None,
    #[allow(missing_docs)] // documentation missing in model
    UseMdpm,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for EmbeddedTimecodeOverride {
    fn from(s: &str) -> Self {
        match s {
            "NONE" => EmbeddedTimecodeOverride::None,
            "USE_MDPM" => EmbeddedTimecodeOverride::UseMdpm,
            other => EmbeddedTimecodeOverride::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for EmbeddedTimecodeOverride {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(EmbeddedTimecodeOverride::from(s))
    }
}
impl EmbeddedTimecodeOverride {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            EmbeddedTimecodeOverride::None => "NONE",
            EmbeddedTimecodeOverride::UseMdpm => "USE_MDPM",
            EmbeddedTimecodeOverride::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["NONE", "USE_MDPM"]
    }
}
impl ::std::convert::AsRef<str> for EmbeddedTimecodeOverride {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl EmbeddedTimecodeOverride {
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
impl ::std::fmt::Display for EmbeddedTimecodeOverride {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            EmbeddedTimecodeOverride::None => write!(f, "NONE"),
            EmbeddedTimecodeOverride::UseMdpm => write!(f, "USE_MDPM"),
            EmbeddedTimecodeOverride::Unknown(value) => write!(f, "{}", value),
        }
    }
}
