// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AnalyticsSessionFilterName`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let analyticssessionfiltername = unimplemented!();
/// match analyticssessionfiltername {
///     AnalyticsSessionFilterName::BotAliasId => { /* ... */ },
///     AnalyticsSessionFilterName::BotVersion => { /* ... */ },
///     AnalyticsSessionFilterName::Channel => { /* ... */ },
///     AnalyticsSessionFilterName::ConversationEndState => { /* ... */ },
///     AnalyticsSessionFilterName::Duration => { /* ... */ },
///     AnalyticsSessionFilterName::IntentPath => { /* ... */ },
///     AnalyticsSessionFilterName::LocaleId => { /* ... */ },
///     AnalyticsSessionFilterName::Modality => { /* ... */ },
///     AnalyticsSessionFilterName::OriginatingRequestId => { /* ... */ },
///     AnalyticsSessionFilterName::SessionId => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `analyticssessionfiltername` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AnalyticsSessionFilterName::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AnalyticsSessionFilterName::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AnalyticsSessionFilterName::NewFeature` is defined.
/// Specifically, when `analyticssessionfiltername` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AnalyticsSessionFilterName::NewFeature` also yielding `"NewFeature"`.
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
pub enum AnalyticsSessionFilterName {
    #[allow(missing_docs)] // documentation missing in model
    BotAliasId,
    #[allow(missing_docs)] // documentation missing in model
    BotVersion,
    #[allow(missing_docs)] // documentation missing in model
    Channel,
    #[allow(missing_docs)] // documentation missing in model
    ConversationEndState,
    #[allow(missing_docs)] // documentation missing in model
    Duration,
    #[allow(missing_docs)] // documentation missing in model
    IntentPath,
    #[allow(missing_docs)] // documentation missing in model
    LocaleId,
    #[allow(missing_docs)] // documentation missing in model
    Modality,
    #[allow(missing_docs)] // documentation missing in model
    OriginatingRequestId,
    #[allow(missing_docs)] // documentation missing in model
    SessionId,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AnalyticsSessionFilterName {
    fn from(s: &str) -> Self {
        match s {
            "BotAliasId" => AnalyticsSessionFilterName::BotAliasId,
            "BotVersion" => AnalyticsSessionFilterName::BotVersion,
            "Channel" => AnalyticsSessionFilterName::Channel,
            "ConversationEndState" => AnalyticsSessionFilterName::ConversationEndState,
            "Duration" => AnalyticsSessionFilterName::Duration,
            "IntentPath" => AnalyticsSessionFilterName::IntentPath,
            "LocaleId" => AnalyticsSessionFilterName::LocaleId,
            "Modality" => AnalyticsSessionFilterName::Modality,
            "OriginatingRequestId" => AnalyticsSessionFilterName::OriginatingRequestId,
            "SessionId" => AnalyticsSessionFilterName::SessionId,
            other => AnalyticsSessionFilterName::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AnalyticsSessionFilterName {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AnalyticsSessionFilterName::from(s))
    }
}
impl AnalyticsSessionFilterName {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AnalyticsSessionFilterName::BotAliasId => "BotAliasId",
            AnalyticsSessionFilterName::BotVersion => "BotVersion",
            AnalyticsSessionFilterName::Channel => "Channel",
            AnalyticsSessionFilterName::ConversationEndState => "ConversationEndState",
            AnalyticsSessionFilterName::Duration => "Duration",
            AnalyticsSessionFilterName::IntentPath => "IntentPath",
            AnalyticsSessionFilterName::LocaleId => "LocaleId",
            AnalyticsSessionFilterName::Modality => "Modality",
            AnalyticsSessionFilterName::OriginatingRequestId => "OriginatingRequestId",
            AnalyticsSessionFilterName::SessionId => "SessionId",
            AnalyticsSessionFilterName::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "BotAliasId",
            "BotVersion",
            "Channel",
            "ConversationEndState",
            "Duration",
            "IntentPath",
            "LocaleId",
            "Modality",
            "OriginatingRequestId",
            "SessionId",
        ]
    }
}
impl ::std::convert::AsRef<str> for AnalyticsSessionFilterName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AnalyticsSessionFilterName {
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
impl ::std::fmt::Display for AnalyticsSessionFilterName {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AnalyticsSessionFilterName::BotAliasId => write!(f, "BotAliasId"),
            AnalyticsSessionFilterName::BotVersion => write!(f, "BotVersion"),
            AnalyticsSessionFilterName::Channel => write!(f, "Channel"),
            AnalyticsSessionFilterName::ConversationEndState => write!(f, "ConversationEndState"),
            AnalyticsSessionFilterName::Duration => write!(f, "Duration"),
            AnalyticsSessionFilterName::IntentPath => write!(f, "IntentPath"),
            AnalyticsSessionFilterName::LocaleId => write!(f, "LocaleId"),
            AnalyticsSessionFilterName::Modality => write!(f, "Modality"),
            AnalyticsSessionFilterName::OriginatingRequestId => write!(f, "OriginatingRequestId"),
            AnalyticsSessionFilterName::SessionId => write!(f, "SessionId"),
            AnalyticsSessionFilterName::Unknown(value) => write!(f, "{}", value),
        }
    }
}
