// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `MlTools`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let mltools = unimplemented!();
/// match mltools {
///     MlTools::AutoMl => { /* ... */ },
///     MlTools::Comet => { /* ... */ },
///     MlTools::DataWrangler => { /* ... */ },
///     MlTools::DeepchecksLlmEvaluation => { /* ... */ },
///     MlTools::EmrClusters => { /* ... */ },
///     MlTools::Endpoints => { /* ... */ },
///     MlTools::Experiments => { /* ... */ },
///     MlTools::FeatureStore => { /* ... */ },
///     MlTools::Fiddler => { /* ... */ },
///     MlTools::HyperPodClusters => { /* ... */ },
///     MlTools::InferenceOptimization => { /* ... */ },
///     MlTools::InferenceRecommender => { /* ... */ },
///     MlTools::JumpStart => { /* ... */ },
///     MlTools::LakeraGuard => { /* ... */ },
///     MlTools::ModelEvaluation => { /* ... */ },
///     MlTools::Models => { /* ... */ },
///     MlTools::PerformanceEvaluation => { /* ... */ },
///     MlTools::Pipelines => { /* ... */ },
///     MlTools::Projects => { /* ... */ },
///     MlTools::Training => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `mltools` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `MlTools::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `MlTools::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `MlTools::NewFeature` is defined.
/// Specifically, when `mltools` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `MlTools::NewFeature` also yielding `"NewFeature"`.
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
pub enum MlTools {
    #[allow(missing_docs)] // documentation missing in model
    AutoMl,
    #[allow(missing_docs)] // documentation missing in model
    Comet,
    #[allow(missing_docs)] // documentation missing in model
    DataWrangler,
    #[allow(missing_docs)] // documentation missing in model
    DeepchecksLlmEvaluation,
    #[allow(missing_docs)] // documentation missing in model
    EmrClusters,
    #[allow(missing_docs)] // documentation missing in model
    Endpoints,
    #[allow(missing_docs)] // documentation missing in model
    Experiments,
    #[allow(missing_docs)] // documentation missing in model
    FeatureStore,
    #[allow(missing_docs)] // documentation missing in model
    Fiddler,
    #[allow(missing_docs)] // documentation missing in model
    HyperPodClusters,
    #[allow(missing_docs)] // documentation missing in model
    InferenceOptimization,
    #[allow(missing_docs)] // documentation missing in model
    InferenceRecommender,
    #[allow(missing_docs)] // documentation missing in model
    JumpStart,
    #[allow(missing_docs)] // documentation missing in model
    LakeraGuard,
    #[allow(missing_docs)] // documentation missing in model
    ModelEvaluation,
    #[allow(missing_docs)] // documentation missing in model
    Models,
    #[allow(missing_docs)] // documentation missing in model
    PerformanceEvaluation,
    #[allow(missing_docs)] // documentation missing in model
    Pipelines,
    #[allow(missing_docs)] // documentation missing in model
    Projects,
    #[allow(missing_docs)] // documentation missing in model
    Training,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for MlTools {
    fn from(s: &str) -> Self {
        match s {
            "AutoMl" => MlTools::AutoMl,
            "Comet" => MlTools::Comet,
            "DataWrangler" => MlTools::DataWrangler,
            "DeepchecksLLMEvaluation" => MlTools::DeepchecksLlmEvaluation,
            "EmrClusters" => MlTools::EmrClusters,
            "Endpoints" => MlTools::Endpoints,
            "Experiments" => MlTools::Experiments,
            "FeatureStore" => MlTools::FeatureStore,
            "Fiddler" => MlTools::Fiddler,
            "HyperPodClusters" => MlTools::HyperPodClusters,
            "InferenceOptimization" => MlTools::InferenceOptimization,
            "InferenceRecommender" => MlTools::InferenceRecommender,
            "JumpStart" => MlTools::JumpStart,
            "LakeraGuard" => MlTools::LakeraGuard,
            "ModelEvaluation" => MlTools::ModelEvaluation,
            "Models" => MlTools::Models,
            "PerformanceEvaluation" => MlTools::PerformanceEvaluation,
            "Pipelines" => MlTools::Pipelines,
            "Projects" => MlTools::Projects,
            "Training" => MlTools::Training,
            other => MlTools::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for MlTools {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(MlTools::from(s))
    }
}
impl MlTools {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            MlTools::AutoMl => "AutoMl",
            MlTools::Comet => "Comet",
            MlTools::DataWrangler => "DataWrangler",
            MlTools::DeepchecksLlmEvaluation => "DeepchecksLLMEvaluation",
            MlTools::EmrClusters => "EmrClusters",
            MlTools::Endpoints => "Endpoints",
            MlTools::Experiments => "Experiments",
            MlTools::FeatureStore => "FeatureStore",
            MlTools::Fiddler => "Fiddler",
            MlTools::HyperPodClusters => "HyperPodClusters",
            MlTools::InferenceOptimization => "InferenceOptimization",
            MlTools::InferenceRecommender => "InferenceRecommender",
            MlTools::JumpStart => "JumpStart",
            MlTools::LakeraGuard => "LakeraGuard",
            MlTools::ModelEvaluation => "ModelEvaluation",
            MlTools::Models => "Models",
            MlTools::PerformanceEvaluation => "PerformanceEvaluation",
            MlTools::Pipelines => "Pipelines",
            MlTools::Projects => "Projects",
            MlTools::Training => "Training",
            MlTools::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AutoMl",
            "Comet",
            "DataWrangler",
            "DeepchecksLLMEvaluation",
            "EmrClusters",
            "Endpoints",
            "Experiments",
            "FeatureStore",
            "Fiddler",
            "HyperPodClusters",
            "InferenceOptimization",
            "InferenceRecommender",
            "JumpStart",
            "LakeraGuard",
            "ModelEvaluation",
            "Models",
            "PerformanceEvaluation",
            "Pipelines",
            "Projects",
            "Training",
        ]
    }
}
impl ::std::convert::AsRef<str> for MlTools {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl MlTools {
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
impl ::std::fmt::Display for MlTools {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            MlTools::AutoMl => write!(f, "AutoMl"),
            MlTools::Comet => write!(f, "Comet"),
            MlTools::DataWrangler => write!(f, "DataWrangler"),
            MlTools::DeepchecksLlmEvaluation => write!(f, "DeepchecksLLMEvaluation"),
            MlTools::EmrClusters => write!(f, "EmrClusters"),
            MlTools::Endpoints => write!(f, "Endpoints"),
            MlTools::Experiments => write!(f, "Experiments"),
            MlTools::FeatureStore => write!(f, "FeatureStore"),
            MlTools::Fiddler => write!(f, "Fiddler"),
            MlTools::HyperPodClusters => write!(f, "HyperPodClusters"),
            MlTools::InferenceOptimization => write!(f, "InferenceOptimization"),
            MlTools::InferenceRecommender => write!(f, "InferenceRecommender"),
            MlTools::JumpStart => write!(f, "JumpStart"),
            MlTools::LakeraGuard => write!(f, "LakeraGuard"),
            MlTools::ModelEvaluation => write!(f, "ModelEvaluation"),
            MlTools::Models => write!(f, "Models"),
            MlTools::PerformanceEvaluation => write!(f, "PerformanceEvaluation"),
            MlTools::Pipelines => write!(f, "Pipelines"),
            MlTools::Projects => write!(f, "Projects"),
            MlTools::Training => write!(f, "Training"),
            MlTools::Unknown(value) => write!(f, "{}", value),
        }
    }
}
