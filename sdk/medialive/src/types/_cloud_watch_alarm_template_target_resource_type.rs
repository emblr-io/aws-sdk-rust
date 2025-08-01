// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `CloudWatchAlarmTemplateTargetResourceType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let cloudwatchalarmtemplatetargetresourcetype = unimplemented!();
/// match cloudwatchalarmtemplatetargetresourcetype {
///     CloudWatchAlarmTemplateTargetResourceType::CloudfrontDistribution => { /* ... */ },
///     CloudWatchAlarmTemplateTargetResourceType::MediaconnectFlow => { /* ... */ },
///     CloudWatchAlarmTemplateTargetResourceType::MedialiveChannel => { /* ... */ },
///     CloudWatchAlarmTemplateTargetResourceType::MedialiveInputDevice => { /* ... */ },
///     CloudWatchAlarmTemplateTargetResourceType::MedialiveMultiplex => { /* ... */ },
///     CloudWatchAlarmTemplateTargetResourceType::MediapackageChannel => { /* ... */ },
///     CloudWatchAlarmTemplateTargetResourceType::MediapackageOriginEndpoint => { /* ... */ },
///     CloudWatchAlarmTemplateTargetResourceType::MediatailorPlaybackConfiguration => { /* ... */ },
///     CloudWatchAlarmTemplateTargetResourceType::S3Bucket => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `cloudwatchalarmtemplatetargetresourcetype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `CloudWatchAlarmTemplateTargetResourceType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `CloudWatchAlarmTemplateTargetResourceType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `CloudWatchAlarmTemplateTargetResourceType::NewFeature` is defined.
/// Specifically, when `cloudwatchalarmtemplatetargetresourcetype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `CloudWatchAlarmTemplateTargetResourceType::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// The resource type this template should dynamically generate cloudwatch metric alarms for.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum CloudWatchAlarmTemplateTargetResourceType {
    #[allow(missing_docs)] // documentation missing in model
    CloudfrontDistribution,
    #[allow(missing_docs)] // documentation missing in model
    MediaconnectFlow,
    #[allow(missing_docs)] // documentation missing in model
    MedialiveChannel,
    #[allow(missing_docs)] // documentation missing in model
    MedialiveInputDevice,
    #[allow(missing_docs)] // documentation missing in model
    MedialiveMultiplex,
    #[allow(missing_docs)] // documentation missing in model
    MediapackageChannel,
    #[allow(missing_docs)] // documentation missing in model
    MediapackageOriginEndpoint,
    #[allow(missing_docs)] // documentation missing in model
    MediatailorPlaybackConfiguration,
    #[allow(missing_docs)] // documentation missing in model
    S3Bucket,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for CloudWatchAlarmTemplateTargetResourceType {
    fn from(s: &str) -> Self {
        match s {
            "CLOUDFRONT_DISTRIBUTION" => CloudWatchAlarmTemplateTargetResourceType::CloudfrontDistribution,
            "MEDIACONNECT_FLOW" => CloudWatchAlarmTemplateTargetResourceType::MediaconnectFlow,
            "MEDIALIVE_CHANNEL" => CloudWatchAlarmTemplateTargetResourceType::MedialiveChannel,
            "MEDIALIVE_INPUT_DEVICE" => CloudWatchAlarmTemplateTargetResourceType::MedialiveInputDevice,
            "MEDIALIVE_MULTIPLEX" => CloudWatchAlarmTemplateTargetResourceType::MedialiveMultiplex,
            "MEDIAPACKAGE_CHANNEL" => CloudWatchAlarmTemplateTargetResourceType::MediapackageChannel,
            "MEDIAPACKAGE_ORIGIN_ENDPOINT" => CloudWatchAlarmTemplateTargetResourceType::MediapackageOriginEndpoint,
            "MEDIATAILOR_PLAYBACK_CONFIGURATION" => CloudWatchAlarmTemplateTargetResourceType::MediatailorPlaybackConfiguration,
            "S3_BUCKET" => CloudWatchAlarmTemplateTargetResourceType::S3Bucket,
            other => {
                CloudWatchAlarmTemplateTargetResourceType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned()))
            }
        }
    }
}
impl ::std::str::FromStr for CloudWatchAlarmTemplateTargetResourceType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(CloudWatchAlarmTemplateTargetResourceType::from(s))
    }
}
impl CloudWatchAlarmTemplateTargetResourceType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            CloudWatchAlarmTemplateTargetResourceType::CloudfrontDistribution => "CLOUDFRONT_DISTRIBUTION",
            CloudWatchAlarmTemplateTargetResourceType::MediaconnectFlow => "MEDIACONNECT_FLOW",
            CloudWatchAlarmTemplateTargetResourceType::MedialiveChannel => "MEDIALIVE_CHANNEL",
            CloudWatchAlarmTemplateTargetResourceType::MedialiveInputDevice => "MEDIALIVE_INPUT_DEVICE",
            CloudWatchAlarmTemplateTargetResourceType::MedialiveMultiplex => "MEDIALIVE_MULTIPLEX",
            CloudWatchAlarmTemplateTargetResourceType::MediapackageChannel => "MEDIAPACKAGE_CHANNEL",
            CloudWatchAlarmTemplateTargetResourceType::MediapackageOriginEndpoint => "MEDIAPACKAGE_ORIGIN_ENDPOINT",
            CloudWatchAlarmTemplateTargetResourceType::MediatailorPlaybackConfiguration => "MEDIATAILOR_PLAYBACK_CONFIGURATION",
            CloudWatchAlarmTemplateTargetResourceType::S3Bucket => "S3_BUCKET",
            CloudWatchAlarmTemplateTargetResourceType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "CLOUDFRONT_DISTRIBUTION",
            "MEDIACONNECT_FLOW",
            "MEDIALIVE_CHANNEL",
            "MEDIALIVE_INPUT_DEVICE",
            "MEDIALIVE_MULTIPLEX",
            "MEDIAPACKAGE_CHANNEL",
            "MEDIAPACKAGE_ORIGIN_ENDPOINT",
            "MEDIATAILOR_PLAYBACK_CONFIGURATION",
            "S3_BUCKET",
        ]
    }
}
impl ::std::convert::AsRef<str> for CloudWatchAlarmTemplateTargetResourceType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl CloudWatchAlarmTemplateTargetResourceType {
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
impl ::std::fmt::Display for CloudWatchAlarmTemplateTargetResourceType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            CloudWatchAlarmTemplateTargetResourceType::CloudfrontDistribution => write!(f, "CLOUDFRONT_DISTRIBUTION"),
            CloudWatchAlarmTemplateTargetResourceType::MediaconnectFlow => write!(f, "MEDIACONNECT_FLOW"),
            CloudWatchAlarmTemplateTargetResourceType::MedialiveChannel => write!(f, "MEDIALIVE_CHANNEL"),
            CloudWatchAlarmTemplateTargetResourceType::MedialiveInputDevice => write!(f, "MEDIALIVE_INPUT_DEVICE"),
            CloudWatchAlarmTemplateTargetResourceType::MedialiveMultiplex => write!(f, "MEDIALIVE_MULTIPLEX"),
            CloudWatchAlarmTemplateTargetResourceType::MediapackageChannel => write!(f, "MEDIAPACKAGE_CHANNEL"),
            CloudWatchAlarmTemplateTargetResourceType::MediapackageOriginEndpoint => write!(f, "MEDIAPACKAGE_ORIGIN_ENDPOINT"),
            CloudWatchAlarmTemplateTargetResourceType::MediatailorPlaybackConfiguration => write!(f, "MEDIATAILOR_PLAYBACK_CONFIGURATION"),
            CloudWatchAlarmTemplateTargetResourceType::S3Bucket => write!(f, "S3_BUCKET"),
            CloudWatchAlarmTemplateTargetResourceType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
