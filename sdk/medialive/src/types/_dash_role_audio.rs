// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `DashRoleAudio`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let dashroleaudio = unimplemented!();
/// match dashroleaudio {
///     DashRoleAudio::Alternate => { /* ... */ },
///     DashRoleAudio::Commentary => { /* ... */ },
///     DashRoleAudio::Description => { /* ... */ },
///     DashRoleAudio::Dub => { /* ... */ },
///     DashRoleAudio::Emergency => { /* ... */ },
///     DashRoleAudio::EnhancedAudioIntelligibility => { /* ... */ },
///     DashRoleAudio::Karaoke => { /* ... */ },
///     DashRoleAudio::Main => { /* ... */ },
///     DashRoleAudio::Supplementary => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `dashroleaudio` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `DashRoleAudio::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `DashRoleAudio::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `DashRoleAudio::NewFeature` is defined.
/// Specifically, when `dashroleaudio` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `DashRoleAudio::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Dash Role Audio
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum DashRoleAudio {
    #[allow(missing_docs)] // documentation missing in model
    Alternate,
    #[allow(missing_docs)] // documentation missing in model
    Commentary,
    #[allow(missing_docs)] // documentation missing in model
    Description,
    #[allow(missing_docs)] // documentation missing in model
    Dub,
    #[allow(missing_docs)] // documentation missing in model
    Emergency,
    #[allow(missing_docs)] // documentation missing in model
    EnhancedAudioIntelligibility,
    #[allow(missing_docs)] // documentation missing in model
    Karaoke,
    #[allow(missing_docs)] // documentation missing in model
    Main,
    #[allow(missing_docs)] // documentation missing in model
    Supplementary,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for DashRoleAudio {
    fn from(s: &str) -> Self {
        match s {
            "ALTERNATE" => DashRoleAudio::Alternate,
            "COMMENTARY" => DashRoleAudio::Commentary,
            "DESCRIPTION" => DashRoleAudio::Description,
            "DUB" => DashRoleAudio::Dub,
            "EMERGENCY" => DashRoleAudio::Emergency,
            "ENHANCED-AUDIO-INTELLIGIBILITY" => DashRoleAudio::EnhancedAudioIntelligibility,
            "KARAOKE" => DashRoleAudio::Karaoke,
            "MAIN" => DashRoleAudio::Main,
            "SUPPLEMENTARY" => DashRoleAudio::Supplementary,
            other => DashRoleAudio::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for DashRoleAudio {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(DashRoleAudio::from(s))
    }
}
impl DashRoleAudio {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            DashRoleAudio::Alternate => "ALTERNATE",
            DashRoleAudio::Commentary => "COMMENTARY",
            DashRoleAudio::Description => "DESCRIPTION",
            DashRoleAudio::Dub => "DUB",
            DashRoleAudio::Emergency => "EMERGENCY",
            DashRoleAudio::EnhancedAudioIntelligibility => "ENHANCED-AUDIO-INTELLIGIBILITY",
            DashRoleAudio::Karaoke => "KARAOKE",
            DashRoleAudio::Main => "MAIN",
            DashRoleAudio::Supplementary => "SUPPLEMENTARY",
            DashRoleAudio::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ALTERNATE",
            "COMMENTARY",
            "DESCRIPTION",
            "DUB",
            "EMERGENCY",
            "ENHANCED-AUDIO-INTELLIGIBILITY",
            "KARAOKE",
            "MAIN",
            "SUPPLEMENTARY",
        ]
    }
}
impl ::std::convert::AsRef<str> for DashRoleAudio {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl DashRoleAudio {
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
impl ::std::fmt::Display for DashRoleAudio {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            DashRoleAudio::Alternate => write!(f, "ALTERNATE"),
            DashRoleAudio::Commentary => write!(f, "COMMENTARY"),
            DashRoleAudio::Description => write!(f, "DESCRIPTION"),
            DashRoleAudio::Dub => write!(f, "DUB"),
            DashRoleAudio::Emergency => write!(f, "EMERGENCY"),
            DashRoleAudio::EnhancedAudioIntelligibility => write!(f, "ENHANCED-AUDIO-INTELLIGIBILITY"),
            DashRoleAudio::Karaoke => write!(f, "KARAOKE"),
            DashRoleAudio::Main => write!(f, "MAIN"),
            DashRoleAudio::Supplementary => write!(f, "SUPPLEMENTARY"),
            DashRoleAudio::Unknown(value) => write!(f, "{}", value),
        }
    }
}
