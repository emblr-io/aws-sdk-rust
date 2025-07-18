// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `CaptionDestinationType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let captiondestinationtype = unimplemented!();
/// match captiondestinationtype {
///     CaptionDestinationType::BurnIn => { /* ... */ },
///     CaptionDestinationType::DvbSub => { /* ... */ },
///     CaptionDestinationType::Embedded => { /* ... */ },
///     CaptionDestinationType::EmbeddedPlusScte20 => { /* ... */ },
///     CaptionDestinationType::Imsc => { /* ... */ },
///     CaptionDestinationType::Scc => { /* ... */ },
///     CaptionDestinationType::Scte20PlusEmbedded => { /* ... */ },
///     CaptionDestinationType::Smi => { /* ... */ },
///     CaptionDestinationType::Srt => { /* ... */ },
///     CaptionDestinationType::Teletext => { /* ... */ },
///     CaptionDestinationType::Ttml => { /* ... */ },
///     CaptionDestinationType::Webvtt => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `captiondestinationtype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `CaptionDestinationType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `CaptionDestinationType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `CaptionDestinationType::NewFeature` is defined.
/// Specifically, when `captiondestinationtype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `CaptionDestinationType::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Specify the format for this set of captions on this output. The default format is embedded without SCTE-20. Note that your choice of video output container constrains your choice of output captions format. For more information, see https://docs.aws.amazon.com/mediaconvert/latest/ug/captions-support-tables.html. If you are using SCTE-20 and you want to create an output that complies with the SCTE-43 spec, choose SCTE-20 plus embedded. To create a non-compliant output where the embedded captions come first, choose Embedded plus SCTE-20.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum CaptionDestinationType {
    #[allow(missing_docs)] // documentation missing in model
    BurnIn,
    #[allow(missing_docs)] // documentation missing in model
    DvbSub,
    #[allow(missing_docs)] // documentation missing in model
    Embedded,
    #[allow(missing_docs)] // documentation missing in model
    EmbeddedPlusScte20,
    #[allow(missing_docs)] // documentation missing in model
    Imsc,
    #[allow(missing_docs)] // documentation missing in model
    Scc,
    #[allow(missing_docs)] // documentation missing in model
    Scte20PlusEmbedded,
    #[allow(missing_docs)] // documentation missing in model
    Smi,
    #[allow(missing_docs)] // documentation missing in model
    Srt,
    #[allow(missing_docs)] // documentation missing in model
    Teletext,
    #[allow(missing_docs)] // documentation missing in model
    Ttml,
    #[allow(missing_docs)] // documentation missing in model
    Webvtt,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for CaptionDestinationType {
    fn from(s: &str) -> Self {
        match s {
            "BURN_IN" => CaptionDestinationType::BurnIn,
            "DVB_SUB" => CaptionDestinationType::DvbSub,
            "EMBEDDED" => CaptionDestinationType::Embedded,
            "EMBEDDED_PLUS_SCTE20" => CaptionDestinationType::EmbeddedPlusScte20,
            "IMSC" => CaptionDestinationType::Imsc,
            "SCC" => CaptionDestinationType::Scc,
            "SCTE20_PLUS_EMBEDDED" => CaptionDestinationType::Scte20PlusEmbedded,
            "SMI" => CaptionDestinationType::Smi,
            "SRT" => CaptionDestinationType::Srt,
            "TELETEXT" => CaptionDestinationType::Teletext,
            "TTML" => CaptionDestinationType::Ttml,
            "WEBVTT" => CaptionDestinationType::Webvtt,
            other => CaptionDestinationType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for CaptionDestinationType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(CaptionDestinationType::from(s))
    }
}
impl CaptionDestinationType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            CaptionDestinationType::BurnIn => "BURN_IN",
            CaptionDestinationType::DvbSub => "DVB_SUB",
            CaptionDestinationType::Embedded => "EMBEDDED",
            CaptionDestinationType::EmbeddedPlusScte20 => "EMBEDDED_PLUS_SCTE20",
            CaptionDestinationType::Imsc => "IMSC",
            CaptionDestinationType::Scc => "SCC",
            CaptionDestinationType::Scte20PlusEmbedded => "SCTE20_PLUS_EMBEDDED",
            CaptionDestinationType::Smi => "SMI",
            CaptionDestinationType::Srt => "SRT",
            CaptionDestinationType::Teletext => "TELETEXT",
            CaptionDestinationType::Ttml => "TTML",
            CaptionDestinationType::Webvtt => "WEBVTT",
            CaptionDestinationType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "BURN_IN",
            "DVB_SUB",
            "EMBEDDED",
            "EMBEDDED_PLUS_SCTE20",
            "IMSC",
            "SCC",
            "SCTE20_PLUS_EMBEDDED",
            "SMI",
            "SRT",
            "TELETEXT",
            "TTML",
            "WEBVTT",
        ]
    }
}
impl ::std::convert::AsRef<str> for CaptionDestinationType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl CaptionDestinationType {
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
impl ::std::fmt::Display for CaptionDestinationType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            CaptionDestinationType::BurnIn => write!(f, "BURN_IN"),
            CaptionDestinationType::DvbSub => write!(f, "DVB_SUB"),
            CaptionDestinationType::Embedded => write!(f, "EMBEDDED"),
            CaptionDestinationType::EmbeddedPlusScte20 => write!(f, "EMBEDDED_PLUS_SCTE20"),
            CaptionDestinationType::Imsc => write!(f, "IMSC"),
            CaptionDestinationType::Scc => write!(f, "SCC"),
            CaptionDestinationType::Scte20PlusEmbedded => write!(f, "SCTE20_PLUS_EMBEDDED"),
            CaptionDestinationType::Smi => write!(f, "SMI"),
            CaptionDestinationType::Srt => write!(f, "SRT"),
            CaptionDestinationType::Teletext => write!(f, "TELETEXT"),
            CaptionDestinationType::Ttml => write!(f, "TTML"),
            CaptionDestinationType::Webvtt => write!(f, "WEBVTT"),
            CaptionDestinationType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
