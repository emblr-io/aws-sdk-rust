// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `OnClusterAppUiType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let onclusterappuitype = unimplemented!();
/// match onclusterappuitype {
///     OnClusterAppUiType::ApplicationMaster => { /* ... */ },
///     OnClusterAppUiType::JobHistoryServer => { /* ... */ },
///     OnClusterAppUiType::ResourceManager => { /* ... */ },
///     OnClusterAppUiType::SparkHistoryServer => { /* ... */ },
///     OnClusterAppUiType::TezUi => { /* ... */ },
///     OnClusterAppUiType::YarnTimelineService => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `onclusterappuitype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `OnClusterAppUiType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `OnClusterAppUiType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `OnClusterAppUiType::NewFeature` is defined.
/// Specifically, when `onclusterappuitype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `OnClusterAppUiType::NewFeature` also yielding `"NewFeature"`.
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
pub enum OnClusterAppUiType {
    #[allow(missing_docs)] // documentation missing in model
    ApplicationMaster,
    #[allow(missing_docs)] // documentation missing in model
    JobHistoryServer,
    #[allow(missing_docs)] // documentation missing in model
    ResourceManager,
    #[allow(missing_docs)] // documentation missing in model
    SparkHistoryServer,
    #[allow(missing_docs)] // documentation missing in model
    TezUi,
    #[allow(missing_docs)] // documentation missing in model
    YarnTimelineService,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for OnClusterAppUiType {
    fn from(s: &str) -> Self {
        match s {
            "ApplicationMaster" => OnClusterAppUiType::ApplicationMaster,
            "JobHistoryServer" => OnClusterAppUiType::JobHistoryServer,
            "ResourceManager" => OnClusterAppUiType::ResourceManager,
            "SparkHistoryServer" => OnClusterAppUiType::SparkHistoryServer,
            "TezUI" => OnClusterAppUiType::TezUi,
            "YarnTimelineService" => OnClusterAppUiType::YarnTimelineService,
            other => OnClusterAppUiType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for OnClusterAppUiType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(OnClusterAppUiType::from(s))
    }
}
impl OnClusterAppUiType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            OnClusterAppUiType::ApplicationMaster => "ApplicationMaster",
            OnClusterAppUiType::JobHistoryServer => "JobHistoryServer",
            OnClusterAppUiType::ResourceManager => "ResourceManager",
            OnClusterAppUiType::SparkHistoryServer => "SparkHistoryServer",
            OnClusterAppUiType::TezUi => "TezUI",
            OnClusterAppUiType::YarnTimelineService => "YarnTimelineService",
            OnClusterAppUiType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ApplicationMaster",
            "JobHistoryServer",
            "ResourceManager",
            "SparkHistoryServer",
            "TezUI",
            "YarnTimelineService",
        ]
    }
}
impl ::std::convert::AsRef<str> for OnClusterAppUiType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl OnClusterAppUiType {
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
impl ::std::fmt::Display for OnClusterAppUiType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            OnClusterAppUiType::ApplicationMaster => write!(f, "ApplicationMaster"),
            OnClusterAppUiType::JobHistoryServer => write!(f, "JobHistoryServer"),
            OnClusterAppUiType::ResourceManager => write!(f, "ResourceManager"),
            OnClusterAppUiType::SparkHistoryServer => write!(f, "SparkHistoryServer"),
            OnClusterAppUiType::TezUi => write!(f, "TezUI"),
            OnClusterAppUiType::YarnTimelineService => write!(f, "YarnTimelineService"),
            OnClusterAppUiType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
