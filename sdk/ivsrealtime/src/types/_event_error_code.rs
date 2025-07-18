// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `EventErrorCode`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let eventerrorcode = unimplemented!();
/// match eventerrorcode {
///     EventErrorCode::BitrateExceeded => { /* ... */ },
///     EventErrorCode::BFramePresent => { /* ... */ },
///     EventErrorCode::InsufficientCapabilities => { /* ... */ },
///     EventErrorCode::InternalServerException => { /* ... */ },
///     EventErrorCode::InvalidAudioCodec => { /* ... */ },
///     EventErrorCode::InvalidInput => { /* ... */ },
///     EventErrorCode::InvalidProtocol => { /* ... */ },
///     EventErrorCode::InvalidStreamKey => { /* ... */ },
///     EventErrorCode::InvalidVideoCodec => { /* ... */ },
///     EventErrorCode::PublisherNotFound => { /* ... */ },
///     EventErrorCode::QuotaExceeded => { /* ... */ },
///     EventErrorCode::ResolutionExceeded => { /* ... */ },
///     EventErrorCode::ReuseOfStreamKey => { /* ... */ },
///     EventErrorCode::StreamDurationExceeded => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `eventerrorcode` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `EventErrorCode::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `EventErrorCode::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `EventErrorCode::NewFeature` is defined.
/// Specifically, when `eventerrorcode` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `EventErrorCode::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum EventErrorCode {
    #[allow(missing_docs)] // documentation missing in model
    BitrateExceeded,
    #[allow(missing_docs)] // documentation missing in model
    BFramePresent,
    #[allow(missing_docs)] // documentation missing in model
    InsufficientCapabilities,
    #[allow(missing_docs)] // documentation missing in model
    InternalServerException,
    #[allow(missing_docs)] // documentation missing in model
    InvalidAudioCodec,
    #[allow(missing_docs)] // documentation missing in model
    InvalidInput,
    #[allow(missing_docs)] // documentation missing in model
    InvalidProtocol,
    #[allow(missing_docs)] // documentation missing in model
    InvalidStreamKey,
    #[allow(missing_docs)] // documentation missing in model
    InvalidVideoCodec,
    #[allow(missing_docs)] // documentation missing in model
    PublisherNotFound,
    #[allow(missing_docs)] // documentation missing in model
    QuotaExceeded,
    #[allow(missing_docs)] // documentation missing in model
    ResolutionExceeded,
    #[allow(missing_docs)] // documentation missing in model
    ReuseOfStreamKey,
    #[allow(missing_docs)] // documentation missing in model
    StreamDurationExceeded,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for EventErrorCode {
    fn from(s: &str) -> Self {
        match s {
            "BITRATE_EXCEEDED" => EventErrorCode::BitrateExceeded,
            "B_FRAME_PRESENT" => EventErrorCode::BFramePresent,
            "INSUFFICIENT_CAPABILITIES" => EventErrorCode::InsufficientCapabilities,
            "INTERNAL_SERVER_EXCEPTION" => EventErrorCode::InternalServerException,
            "INVALID_AUDIO_CODEC" => EventErrorCode::InvalidAudioCodec,
            "INVALID_INPUT" => EventErrorCode::InvalidInput,
            "INVALID_PROTOCOL" => EventErrorCode::InvalidProtocol,
            "INVALID_STREAM_KEY" => EventErrorCode::InvalidStreamKey,
            "INVALID_VIDEO_CODEC" => EventErrorCode::InvalidVideoCodec,
            "PUBLISHER_NOT_FOUND" => EventErrorCode::PublisherNotFound,
            "QUOTA_EXCEEDED" => EventErrorCode::QuotaExceeded,
            "RESOLUTION_EXCEEDED" => EventErrorCode::ResolutionExceeded,
            "REUSE_OF_STREAM_KEY" => EventErrorCode::ReuseOfStreamKey,
            "STREAM_DURATION_EXCEEDED" => EventErrorCode::StreamDurationExceeded,
            other => EventErrorCode::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for EventErrorCode {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(EventErrorCode::from(s))
    }
}
impl EventErrorCode {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            EventErrorCode::BitrateExceeded => "BITRATE_EXCEEDED",
            EventErrorCode::BFramePresent => "B_FRAME_PRESENT",
            EventErrorCode::InsufficientCapabilities => "INSUFFICIENT_CAPABILITIES",
            EventErrorCode::InternalServerException => "INTERNAL_SERVER_EXCEPTION",
            EventErrorCode::InvalidAudioCodec => "INVALID_AUDIO_CODEC",
            EventErrorCode::InvalidInput => "INVALID_INPUT",
            EventErrorCode::InvalidProtocol => "INVALID_PROTOCOL",
            EventErrorCode::InvalidStreamKey => "INVALID_STREAM_KEY",
            EventErrorCode::InvalidVideoCodec => "INVALID_VIDEO_CODEC",
            EventErrorCode::PublisherNotFound => "PUBLISHER_NOT_FOUND",
            EventErrorCode::QuotaExceeded => "QUOTA_EXCEEDED",
            EventErrorCode::ResolutionExceeded => "RESOLUTION_EXCEEDED",
            EventErrorCode::ReuseOfStreamKey => "REUSE_OF_STREAM_KEY",
            EventErrorCode::StreamDurationExceeded => "STREAM_DURATION_EXCEEDED",
            EventErrorCode::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "BITRATE_EXCEEDED",
            "B_FRAME_PRESENT",
            "INSUFFICIENT_CAPABILITIES",
            "INTERNAL_SERVER_EXCEPTION",
            "INVALID_AUDIO_CODEC",
            "INVALID_INPUT",
            "INVALID_PROTOCOL",
            "INVALID_STREAM_KEY",
            "INVALID_VIDEO_CODEC",
            "PUBLISHER_NOT_FOUND",
            "QUOTA_EXCEEDED",
            "RESOLUTION_EXCEEDED",
            "REUSE_OF_STREAM_KEY",
            "STREAM_DURATION_EXCEEDED",
        ]
    }
}
impl ::std::convert::AsRef<str> for EventErrorCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl EventErrorCode {
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
impl ::std::fmt::Display for EventErrorCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            EventErrorCode::BitrateExceeded => write!(f, "BITRATE_EXCEEDED"),
            EventErrorCode::BFramePresent => write!(f, "B_FRAME_PRESENT"),
            EventErrorCode::InsufficientCapabilities => write!(f, "INSUFFICIENT_CAPABILITIES"),
            EventErrorCode::InternalServerException => write!(f, "INTERNAL_SERVER_EXCEPTION"),
            EventErrorCode::InvalidAudioCodec => write!(f, "INVALID_AUDIO_CODEC"),
            EventErrorCode::InvalidInput => write!(f, "INVALID_INPUT"),
            EventErrorCode::InvalidProtocol => write!(f, "INVALID_PROTOCOL"),
            EventErrorCode::InvalidStreamKey => write!(f, "INVALID_STREAM_KEY"),
            EventErrorCode::InvalidVideoCodec => write!(f, "INVALID_VIDEO_CODEC"),
            EventErrorCode::PublisherNotFound => write!(f, "PUBLISHER_NOT_FOUND"),
            EventErrorCode::QuotaExceeded => write!(f, "QUOTA_EXCEEDED"),
            EventErrorCode::ResolutionExceeded => write!(f, "RESOLUTION_EXCEEDED"),
            EventErrorCode::ReuseOfStreamKey => write!(f, "REUSE_OF_STREAM_KEY"),
            EventErrorCode::StreamDurationExceeded => write!(f, "STREAM_DURATION_EXCEEDED"),
            EventErrorCode::Unknown(value) => write!(f, "{}", value),
        }
    }
}
