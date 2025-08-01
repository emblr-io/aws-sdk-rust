// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ContainerType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let containertype = unimplemented!();
/// match containertype {
///     ContainerType::Cmfc => { /* ... */ },
///     ContainerType::F4V => { /* ... */ },
///     ContainerType::Gif => { /* ... */ },
///     ContainerType::Ismv => { /* ... */ },
///     ContainerType::M2Ts => { /* ... */ },
///     ContainerType::M3U8 => { /* ... */ },
///     ContainerType::Mov => { /* ... */ },
///     ContainerType::Mp4 => { /* ... */ },
///     ContainerType::Mpd => { /* ... */ },
///     ContainerType::Mxf => { /* ... */ },
///     ContainerType::Ogg => { /* ... */ },
///     ContainerType::Raw => { /* ... */ },
///     ContainerType::Webm => { /* ... */ },
///     ContainerType::Y4M => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `containertype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ContainerType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ContainerType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ContainerType::NewFeature` is defined.
/// Specifically, when `containertype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ContainerType::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Container for this output. Some containers require a container settings object. If not specified, the default object will be created.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum ContainerType {
    #[allow(missing_docs)] // documentation missing in model
    Cmfc,
    #[allow(missing_docs)] // documentation missing in model
    F4V,
    #[allow(missing_docs)] // documentation missing in model
    Gif,
    #[allow(missing_docs)] // documentation missing in model
    Ismv,
    #[allow(missing_docs)] // documentation missing in model
    M2Ts,
    #[allow(missing_docs)] // documentation missing in model
    M3U8,
    #[allow(missing_docs)] // documentation missing in model
    Mov,
    #[allow(missing_docs)] // documentation missing in model
    Mp4,
    #[allow(missing_docs)] // documentation missing in model
    Mpd,
    #[allow(missing_docs)] // documentation missing in model
    Mxf,
    #[allow(missing_docs)] // documentation missing in model
    Ogg,
    #[allow(missing_docs)] // documentation missing in model
    Raw,
    #[allow(missing_docs)] // documentation missing in model
    Webm,
    #[allow(missing_docs)] // documentation missing in model
    Y4M,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ContainerType {
    fn from(s: &str) -> Self {
        match s {
            "CMFC" => ContainerType::Cmfc,
            "F4V" => ContainerType::F4V,
            "GIF" => ContainerType::Gif,
            "ISMV" => ContainerType::Ismv,
            "M2TS" => ContainerType::M2Ts,
            "M3U8" => ContainerType::M3U8,
            "MOV" => ContainerType::Mov,
            "MP4" => ContainerType::Mp4,
            "MPD" => ContainerType::Mpd,
            "MXF" => ContainerType::Mxf,
            "OGG" => ContainerType::Ogg,
            "RAW" => ContainerType::Raw,
            "WEBM" => ContainerType::Webm,
            "Y4M" => ContainerType::Y4M,
            other => ContainerType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ContainerType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ContainerType::from(s))
    }
}
impl ContainerType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ContainerType::Cmfc => "CMFC",
            ContainerType::F4V => "F4V",
            ContainerType::Gif => "GIF",
            ContainerType::Ismv => "ISMV",
            ContainerType::M2Ts => "M2TS",
            ContainerType::M3U8 => "M3U8",
            ContainerType::Mov => "MOV",
            ContainerType::Mp4 => "MP4",
            ContainerType::Mpd => "MPD",
            ContainerType::Mxf => "MXF",
            ContainerType::Ogg => "OGG",
            ContainerType::Raw => "RAW",
            ContainerType::Webm => "WEBM",
            ContainerType::Y4M => "Y4M",
            ContainerType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "CMFC", "F4V", "GIF", "ISMV", "M2TS", "M3U8", "MOV", "MP4", "MPD", "MXF", "OGG", "RAW", "WEBM", "Y4M",
        ]
    }
}
impl ::std::convert::AsRef<str> for ContainerType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ContainerType {
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
impl ::std::fmt::Display for ContainerType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ContainerType::Cmfc => write!(f, "CMFC"),
            ContainerType::F4V => write!(f, "F4V"),
            ContainerType::Gif => write!(f, "GIF"),
            ContainerType::Ismv => write!(f, "ISMV"),
            ContainerType::M2Ts => write!(f, "M2TS"),
            ContainerType::M3U8 => write!(f, "M3U8"),
            ContainerType::Mov => write!(f, "MOV"),
            ContainerType::Mp4 => write!(f, "MP4"),
            ContainerType::Mpd => write!(f, "MPD"),
            ContainerType::Mxf => write!(f, "MXF"),
            ContainerType::Ogg => write!(f, "OGG"),
            ContainerType::Raw => write!(f, "RAW"),
            ContainerType::Webm => write!(f, "WEBM"),
            ContainerType::Y4M => write!(f, "Y4M"),
            ContainerType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
