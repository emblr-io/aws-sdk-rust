// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `MediaInsightsPipelineConfigurationElementType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let mediainsightspipelineconfigurationelementtype = unimplemented!();
/// match mediainsightspipelineconfigurationelementtype {
///     MediaInsightsPipelineConfigurationElementType::AmazonTranscribeCallAnalyticsProcessor => { /* ... */ },
///     MediaInsightsPipelineConfigurationElementType::AmazonTranscribeProcessor => { /* ... */ },
///     MediaInsightsPipelineConfigurationElementType::KinesisDataStreamSink => { /* ... */ },
///     MediaInsightsPipelineConfigurationElementType::LambdaFunctionSink => { /* ... */ },
///     MediaInsightsPipelineConfigurationElementType::S3RecordingSink => { /* ... */ },
///     MediaInsightsPipelineConfigurationElementType::SnsTopicSink => { /* ... */ },
///     MediaInsightsPipelineConfigurationElementType::SqsQueueSink => { /* ... */ },
///     MediaInsightsPipelineConfigurationElementType::VoiceAnalyticsProcessor => { /* ... */ },
///     MediaInsightsPipelineConfigurationElementType::VoiceEnhancementSink => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `mediainsightspipelineconfigurationelementtype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `MediaInsightsPipelineConfigurationElementType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `MediaInsightsPipelineConfigurationElementType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `MediaInsightsPipelineConfigurationElementType::NewFeature` is defined.
/// Specifically, when `mediainsightspipelineconfigurationelementtype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `MediaInsightsPipelineConfigurationElementType::NewFeature` also yielding `"NewFeature"`.
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
pub enum MediaInsightsPipelineConfigurationElementType {
    #[allow(missing_docs)] // documentation missing in model
    AmazonTranscribeCallAnalyticsProcessor,
    #[allow(missing_docs)] // documentation missing in model
    AmazonTranscribeProcessor,
    #[allow(missing_docs)] // documentation missing in model
    KinesisDataStreamSink,
    #[allow(missing_docs)] // documentation missing in model
    LambdaFunctionSink,
    #[allow(missing_docs)] // documentation missing in model
    S3RecordingSink,
    #[allow(missing_docs)] // documentation missing in model
    SnsTopicSink,
    #[allow(missing_docs)] // documentation missing in model
    SqsQueueSink,
    #[allow(missing_docs)] // documentation missing in model
    VoiceAnalyticsProcessor,
    #[allow(missing_docs)] // documentation missing in model
    VoiceEnhancementSink,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for MediaInsightsPipelineConfigurationElementType {
    fn from(s: &str) -> Self {
        match s {
            "AmazonTranscribeCallAnalyticsProcessor" => MediaInsightsPipelineConfigurationElementType::AmazonTranscribeCallAnalyticsProcessor,
            "AmazonTranscribeProcessor" => MediaInsightsPipelineConfigurationElementType::AmazonTranscribeProcessor,
            "KinesisDataStreamSink" => MediaInsightsPipelineConfigurationElementType::KinesisDataStreamSink,
            "LambdaFunctionSink" => MediaInsightsPipelineConfigurationElementType::LambdaFunctionSink,
            "S3RecordingSink" => MediaInsightsPipelineConfigurationElementType::S3RecordingSink,
            "SnsTopicSink" => MediaInsightsPipelineConfigurationElementType::SnsTopicSink,
            "SqsQueueSink" => MediaInsightsPipelineConfigurationElementType::SqsQueueSink,
            "VoiceAnalyticsProcessor" => MediaInsightsPipelineConfigurationElementType::VoiceAnalyticsProcessor,
            "VoiceEnhancementSink" => MediaInsightsPipelineConfigurationElementType::VoiceEnhancementSink,
            other => {
                MediaInsightsPipelineConfigurationElementType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned()))
            }
        }
    }
}
impl ::std::str::FromStr for MediaInsightsPipelineConfigurationElementType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(MediaInsightsPipelineConfigurationElementType::from(s))
    }
}
impl MediaInsightsPipelineConfigurationElementType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            MediaInsightsPipelineConfigurationElementType::AmazonTranscribeCallAnalyticsProcessor => "AmazonTranscribeCallAnalyticsProcessor",
            MediaInsightsPipelineConfigurationElementType::AmazonTranscribeProcessor => "AmazonTranscribeProcessor",
            MediaInsightsPipelineConfigurationElementType::KinesisDataStreamSink => "KinesisDataStreamSink",
            MediaInsightsPipelineConfigurationElementType::LambdaFunctionSink => "LambdaFunctionSink",
            MediaInsightsPipelineConfigurationElementType::S3RecordingSink => "S3RecordingSink",
            MediaInsightsPipelineConfigurationElementType::SnsTopicSink => "SnsTopicSink",
            MediaInsightsPipelineConfigurationElementType::SqsQueueSink => "SqsQueueSink",
            MediaInsightsPipelineConfigurationElementType::VoiceAnalyticsProcessor => "VoiceAnalyticsProcessor",
            MediaInsightsPipelineConfigurationElementType::VoiceEnhancementSink => "VoiceEnhancementSink",
            MediaInsightsPipelineConfigurationElementType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AmazonTranscribeCallAnalyticsProcessor",
            "AmazonTranscribeProcessor",
            "KinesisDataStreamSink",
            "LambdaFunctionSink",
            "S3RecordingSink",
            "SnsTopicSink",
            "SqsQueueSink",
            "VoiceAnalyticsProcessor",
            "VoiceEnhancementSink",
        ]
    }
}
impl ::std::convert::AsRef<str> for MediaInsightsPipelineConfigurationElementType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl MediaInsightsPipelineConfigurationElementType {
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
impl ::std::fmt::Display for MediaInsightsPipelineConfigurationElementType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            MediaInsightsPipelineConfigurationElementType::AmazonTranscribeCallAnalyticsProcessor => {
                write!(f, "AmazonTranscribeCallAnalyticsProcessor")
            }
            MediaInsightsPipelineConfigurationElementType::AmazonTranscribeProcessor => write!(f, "AmazonTranscribeProcessor"),
            MediaInsightsPipelineConfigurationElementType::KinesisDataStreamSink => write!(f, "KinesisDataStreamSink"),
            MediaInsightsPipelineConfigurationElementType::LambdaFunctionSink => write!(f, "LambdaFunctionSink"),
            MediaInsightsPipelineConfigurationElementType::S3RecordingSink => write!(f, "S3RecordingSink"),
            MediaInsightsPipelineConfigurationElementType::SnsTopicSink => write!(f, "SnsTopicSink"),
            MediaInsightsPipelineConfigurationElementType::SqsQueueSink => write!(f, "SqsQueueSink"),
            MediaInsightsPipelineConfigurationElementType::VoiceAnalyticsProcessor => write!(f, "VoiceAnalyticsProcessor"),
            MediaInsightsPipelineConfigurationElementType::VoiceEnhancementSink => write!(f, "VoiceEnhancementSink"),
            MediaInsightsPipelineConfigurationElementType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
