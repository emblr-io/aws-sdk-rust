// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ExportableLambdaFunctionField`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let exportablelambdafunctionfield = unimplemented!();
/// match exportablelambdafunctionfield {
///     ExportableLambdaFunctionField::AccountId => { /* ... */ },
///     ExportableLambdaFunctionField::CurrentConfigurationMemorySize => { /* ... */ },
///     ExportableLambdaFunctionField::CurrentConfigurationTimeout => { /* ... */ },
///     ExportableLambdaFunctionField::CurrentCostAverage => { /* ... */ },
///     ExportableLambdaFunctionField::CurrentCostTotal => { /* ... */ },
///     ExportableLambdaFunctionField::CurrentPerformanceRisk => { /* ... */ },
///     ExportableLambdaFunctionField::EffectiveRecommendationPreferencesSavingsEstimationMode => { /* ... */ },
///     ExportableLambdaFunctionField::Finding => { /* ... */ },
///     ExportableLambdaFunctionField::FindingReasonCodes => { /* ... */ },
///     ExportableLambdaFunctionField::FunctionArn => { /* ... */ },
///     ExportableLambdaFunctionField::FunctionVersion => { /* ... */ },
///     ExportableLambdaFunctionField::LastRefreshTimestamp => { /* ... */ },
///     ExportableLambdaFunctionField::LookbackPeriodInDays => { /* ... */ },
///     ExportableLambdaFunctionField::NumberOfInvocations => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsConfigurationMemorySize => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsCostHigh => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsCostLow => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsCurrency => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsCurrencyAfterDiscounts => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsValue => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsValueAfterDiscounts => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationExpected => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationLowerBound => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationUpperBound => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsSavingsOpportunityAfterDiscountsPercentage => { /* ... */ },
///     ExportableLambdaFunctionField::RecommendationOptionsSavingsOpportunityPercentage => { /* ... */ },
///     ExportableLambdaFunctionField::Tags => { /* ... */ },
///     ExportableLambdaFunctionField::UtilizationMetricsDurationAverage => { /* ... */ },
///     ExportableLambdaFunctionField::UtilizationMetricsDurationMaximum => { /* ... */ },
///     ExportableLambdaFunctionField::UtilizationMetricsMemoryAverage => { /* ... */ },
///     ExportableLambdaFunctionField::UtilizationMetricsMemoryMaximum => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `exportablelambdafunctionfield` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ExportableLambdaFunctionField::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ExportableLambdaFunctionField::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ExportableLambdaFunctionField::NewFeature` is defined.
/// Specifically, when `exportablelambdafunctionfield` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ExportableLambdaFunctionField::NewFeature` also yielding `"NewFeature"`.
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
pub enum ExportableLambdaFunctionField {
    #[allow(missing_docs)] // documentation missing in model
    AccountId,
    #[allow(missing_docs)] // documentation missing in model
    CurrentConfigurationMemorySize,
    #[allow(missing_docs)] // documentation missing in model
    CurrentConfigurationTimeout,
    #[allow(missing_docs)] // documentation missing in model
    CurrentCostAverage,
    #[allow(missing_docs)] // documentation missing in model
    CurrentCostTotal,
    #[allow(missing_docs)] // documentation missing in model
    CurrentPerformanceRisk,
    #[allow(missing_docs)] // documentation missing in model
    EffectiveRecommendationPreferencesSavingsEstimationMode,
    #[allow(missing_docs)] // documentation missing in model
    Finding,
    #[allow(missing_docs)] // documentation missing in model
    FindingReasonCodes,
    #[allow(missing_docs)] // documentation missing in model
    FunctionArn,
    #[allow(missing_docs)] // documentation missing in model
    FunctionVersion,
    #[allow(missing_docs)] // documentation missing in model
    LastRefreshTimestamp,
    #[allow(missing_docs)] // documentation missing in model
    LookbackPeriodInDays,
    #[allow(missing_docs)] // documentation missing in model
    NumberOfInvocations,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsConfigurationMemorySize,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsCostHigh,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsCostLow,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsEstimatedMonthlySavingsCurrency,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsEstimatedMonthlySavingsCurrencyAfterDiscounts,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsEstimatedMonthlySavingsValue,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsEstimatedMonthlySavingsValueAfterDiscounts,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsProjectedUtilizationMetricsDurationExpected,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsProjectedUtilizationMetricsDurationLowerBound,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsProjectedUtilizationMetricsDurationUpperBound,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsSavingsOpportunityAfterDiscountsPercentage,
    #[allow(missing_docs)] // documentation missing in model
    RecommendationOptionsSavingsOpportunityPercentage,
    #[allow(missing_docs)] // documentation missing in model
    Tags,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsDurationAverage,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsDurationMaximum,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsMemoryAverage,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsMemoryMaximum,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ExportableLambdaFunctionField {
    fn from(s: &str) -> Self {
        match s {
            "AccountId" => ExportableLambdaFunctionField::AccountId,
            "CurrentConfigurationMemorySize" => ExportableLambdaFunctionField::CurrentConfigurationMemorySize,
            "CurrentConfigurationTimeout" => ExportableLambdaFunctionField::CurrentConfigurationTimeout,
            "CurrentCostAverage" => ExportableLambdaFunctionField::CurrentCostAverage,
            "CurrentCostTotal" => ExportableLambdaFunctionField::CurrentCostTotal,
            "CurrentPerformanceRisk" => ExportableLambdaFunctionField::CurrentPerformanceRisk,
            "EffectiveRecommendationPreferencesSavingsEstimationMode" => {
                ExportableLambdaFunctionField::EffectiveRecommendationPreferencesSavingsEstimationMode
            }
            "Finding" => ExportableLambdaFunctionField::Finding,
            "FindingReasonCodes" => ExportableLambdaFunctionField::FindingReasonCodes,
            "FunctionArn" => ExportableLambdaFunctionField::FunctionArn,
            "FunctionVersion" => ExportableLambdaFunctionField::FunctionVersion,
            "LastRefreshTimestamp" => ExportableLambdaFunctionField::LastRefreshTimestamp,
            "LookbackPeriodInDays" => ExportableLambdaFunctionField::LookbackPeriodInDays,
            "NumberOfInvocations" => ExportableLambdaFunctionField::NumberOfInvocations,
            "RecommendationOptionsConfigurationMemorySize" => ExportableLambdaFunctionField::RecommendationOptionsConfigurationMemorySize,
            "RecommendationOptionsCostHigh" => ExportableLambdaFunctionField::RecommendationOptionsCostHigh,
            "RecommendationOptionsCostLow" => ExportableLambdaFunctionField::RecommendationOptionsCostLow,
            "RecommendationOptionsEstimatedMonthlySavingsCurrency" => {
                ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsCurrency
            }
            "RecommendationOptionsEstimatedMonthlySavingsCurrencyAfterDiscounts" => {
                ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsCurrencyAfterDiscounts
            }
            "RecommendationOptionsEstimatedMonthlySavingsValue" => ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsValue,
            "RecommendationOptionsEstimatedMonthlySavingsValueAfterDiscounts" => {
                ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsValueAfterDiscounts
            }
            "RecommendationOptionsProjectedUtilizationMetricsDurationExpected" => {
                ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationExpected
            }
            "RecommendationOptionsProjectedUtilizationMetricsDurationLowerBound" => {
                ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationLowerBound
            }
            "RecommendationOptionsProjectedUtilizationMetricsDurationUpperBound" => {
                ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationUpperBound
            }
            "RecommendationOptionsSavingsOpportunityAfterDiscountsPercentage" => {
                ExportableLambdaFunctionField::RecommendationOptionsSavingsOpportunityAfterDiscountsPercentage
            }
            "RecommendationOptionsSavingsOpportunityPercentage" => ExportableLambdaFunctionField::RecommendationOptionsSavingsOpportunityPercentage,
            "Tags" => ExportableLambdaFunctionField::Tags,
            "UtilizationMetricsDurationAverage" => ExportableLambdaFunctionField::UtilizationMetricsDurationAverage,
            "UtilizationMetricsDurationMaximum" => ExportableLambdaFunctionField::UtilizationMetricsDurationMaximum,
            "UtilizationMetricsMemoryAverage" => ExportableLambdaFunctionField::UtilizationMetricsMemoryAverage,
            "UtilizationMetricsMemoryMaximum" => ExportableLambdaFunctionField::UtilizationMetricsMemoryMaximum,
            other => ExportableLambdaFunctionField::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ExportableLambdaFunctionField {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ExportableLambdaFunctionField::from(s))
    }
}
impl ExportableLambdaFunctionField {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ExportableLambdaFunctionField::AccountId => "AccountId",
            ExportableLambdaFunctionField::CurrentConfigurationMemorySize => "CurrentConfigurationMemorySize",
            ExportableLambdaFunctionField::CurrentConfigurationTimeout => "CurrentConfigurationTimeout",
            ExportableLambdaFunctionField::CurrentCostAverage => "CurrentCostAverage",
            ExportableLambdaFunctionField::CurrentCostTotal => "CurrentCostTotal",
            ExportableLambdaFunctionField::CurrentPerformanceRisk => "CurrentPerformanceRisk",
            ExportableLambdaFunctionField::EffectiveRecommendationPreferencesSavingsEstimationMode => {
                "EffectiveRecommendationPreferencesSavingsEstimationMode"
            }
            ExportableLambdaFunctionField::Finding => "Finding",
            ExportableLambdaFunctionField::FindingReasonCodes => "FindingReasonCodes",
            ExportableLambdaFunctionField::FunctionArn => "FunctionArn",
            ExportableLambdaFunctionField::FunctionVersion => "FunctionVersion",
            ExportableLambdaFunctionField::LastRefreshTimestamp => "LastRefreshTimestamp",
            ExportableLambdaFunctionField::LookbackPeriodInDays => "LookbackPeriodInDays",
            ExportableLambdaFunctionField::NumberOfInvocations => "NumberOfInvocations",
            ExportableLambdaFunctionField::RecommendationOptionsConfigurationMemorySize => "RecommendationOptionsConfigurationMemorySize",
            ExportableLambdaFunctionField::RecommendationOptionsCostHigh => "RecommendationOptionsCostHigh",
            ExportableLambdaFunctionField::RecommendationOptionsCostLow => "RecommendationOptionsCostLow",
            ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsCurrency => {
                "RecommendationOptionsEstimatedMonthlySavingsCurrency"
            }
            ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsCurrencyAfterDiscounts => {
                "RecommendationOptionsEstimatedMonthlySavingsCurrencyAfterDiscounts"
            }
            ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsValue => "RecommendationOptionsEstimatedMonthlySavingsValue",
            ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsValueAfterDiscounts => {
                "RecommendationOptionsEstimatedMonthlySavingsValueAfterDiscounts"
            }
            ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationExpected => {
                "RecommendationOptionsProjectedUtilizationMetricsDurationExpected"
            }
            ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationLowerBound => {
                "RecommendationOptionsProjectedUtilizationMetricsDurationLowerBound"
            }
            ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationUpperBound => {
                "RecommendationOptionsProjectedUtilizationMetricsDurationUpperBound"
            }
            ExportableLambdaFunctionField::RecommendationOptionsSavingsOpportunityAfterDiscountsPercentage => {
                "RecommendationOptionsSavingsOpportunityAfterDiscountsPercentage"
            }
            ExportableLambdaFunctionField::RecommendationOptionsSavingsOpportunityPercentage => "RecommendationOptionsSavingsOpportunityPercentage",
            ExportableLambdaFunctionField::Tags => "Tags",
            ExportableLambdaFunctionField::UtilizationMetricsDurationAverage => "UtilizationMetricsDurationAverage",
            ExportableLambdaFunctionField::UtilizationMetricsDurationMaximum => "UtilizationMetricsDurationMaximum",
            ExportableLambdaFunctionField::UtilizationMetricsMemoryAverage => "UtilizationMetricsMemoryAverage",
            ExportableLambdaFunctionField::UtilizationMetricsMemoryMaximum => "UtilizationMetricsMemoryMaximum",
            ExportableLambdaFunctionField::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AccountId",
            "CurrentConfigurationMemorySize",
            "CurrentConfigurationTimeout",
            "CurrentCostAverage",
            "CurrentCostTotal",
            "CurrentPerformanceRisk",
            "EffectiveRecommendationPreferencesSavingsEstimationMode",
            "Finding",
            "FindingReasonCodes",
            "FunctionArn",
            "FunctionVersion",
            "LastRefreshTimestamp",
            "LookbackPeriodInDays",
            "NumberOfInvocations",
            "RecommendationOptionsConfigurationMemorySize",
            "RecommendationOptionsCostHigh",
            "RecommendationOptionsCostLow",
            "RecommendationOptionsEstimatedMonthlySavingsCurrency",
            "RecommendationOptionsEstimatedMonthlySavingsCurrencyAfterDiscounts",
            "RecommendationOptionsEstimatedMonthlySavingsValue",
            "RecommendationOptionsEstimatedMonthlySavingsValueAfterDiscounts",
            "RecommendationOptionsProjectedUtilizationMetricsDurationExpected",
            "RecommendationOptionsProjectedUtilizationMetricsDurationLowerBound",
            "RecommendationOptionsProjectedUtilizationMetricsDurationUpperBound",
            "RecommendationOptionsSavingsOpportunityAfterDiscountsPercentage",
            "RecommendationOptionsSavingsOpportunityPercentage",
            "Tags",
            "UtilizationMetricsDurationAverage",
            "UtilizationMetricsDurationMaximum",
            "UtilizationMetricsMemoryAverage",
            "UtilizationMetricsMemoryMaximum",
        ]
    }
}
impl ::std::convert::AsRef<str> for ExportableLambdaFunctionField {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ExportableLambdaFunctionField {
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
impl ::std::fmt::Display for ExportableLambdaFunctionField {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ExportableLambdaFunctionField::AccountId => write!(f, "AccountId"),
            ExportableLambdaFunctionField::CurrentConfigurationMemorySize => write!(f, "CurrentConfigurationMemorySize"),
            ExportableLambdaFunctionField::CurrentConfigurationTimeout => write!(f, "CurrentConfigurationTimeout"),
            ExportableLambdaFunctionField::CurrentCostAverage => write!(f, "CurrentCostAverage"),
            ExportableLambdaFunctionField::CurrentCostTotal => write!(f, "CurrentCostTotal"),
            ExportableLambdaFunctionField::CurrentPerformanceRisk => write!(f, "CurrentPerformanceRisk"),
            ExportableLambdaFunctionField::EffectiveRecommendationPreferencesSavingsEstimationMode => {
                write!(f, "EffectiveRecommendationPreferencesSavingsEstimationMode")
            }
            ExportableLambdaFunctionField::Finding => write!(f, "Finding"),
            ExportableLambdaFunctionField::FindingReasonCodes => write!(f, "FindingReasonCodes"),
            ExportableLambdaFunctionField::FunctionArn => write!(f, "FunctionArn"),
            ExportableLambdaFunctionField::FunctionVersion => write!(f, "FunctionVersion"),
            ExportableLambdaFunctionField::LastRefreshTimestamp => write!(f, "LastRefreshTimestamp"),
            ExportableLambdaFunctionField::LookbackPeriodInDays => write!(f, "LookbackPeriodInDays"),
            ExportableLambdaFunctionField::NumberOfInvocations => write!(f, "NumberOfInvocations"),
            ExportableLambdaFunctionField::RecommendationOptionsConfigurationMemorySize => write!(f, "RecommendationOptionsConfigurationMemorySize"),
            ExportableLambdaFunctionField::RecommendationOptionsCostHigh => write!(f, "RecommendationOptionsCostHigh"),
            ExportableLambdaFunctionField::RecommendationOptionsCostLow => write!(f, "RecommendationOptionsCostLow"),
            ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsCurrency => {
                write!(f, "RecommendationOptionsEstimatedMonthlySavingsCurrency")
            }
            ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsCurrencyAfterDiscounts => {
                write!(f, "RecommendationOptionsEstimatedMonthlySavingsCurrencyAfterDiscounts")
            }
            ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsValue => {
                write!(f, "RecommendationOptionsEstimatedMonthlySavingsValue")
            }
            ExportableLambdaFunctionField::RecommendationOptionsEstimatedMonthlySavingsValueAfterDiscounts => {
                write!(f, "RecommendationOptionsEstimatedMonthlySavingsValueAfterDiscounts")
            }
            ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationExpected => {
                write!(f, "RecommendationOptionsProjectedUtilizationMetricsDurationExpected")
            }
            ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationLowerBound => {
                write!(f, "RecommendationOptionsProjectedUtilizationMetricsDurationLowerBound")
            }
            ExportableLambdaFunctionField::RecommendationOptionsProjectedUtilizationMetricsDurationUpperBound => {
                write!(f, "RecommendationOptionsProjectedUtilizationMetricsDurationUpperBound")
            }
            ExportableLambdaFunctionField::RecommendationOptionsSavingsOpportunityAfterDiscountsPercentage => {
                write!(f, "RecommendationOptionsSavingsOpportunityAfterDiscountsPercentage")
            }
            ExportableLambdaFunctionField::RecommendationOptionsSavingsOpportunityPercentage => {
                write!(f, "RecommendationOptionsSavingsOpportunityPercentage")
            }
            ExportableLambdaFunctionField::Tags => write!(f, "Tags"),
            ExportableLambdaFunctionField::UtilizationMetricsDurationAverage => write!(f, "UtilizationMetricsDurationAverage"),
            ExportableLambdaFunctionField::UtilizationMetricsDurationMaximum => write!(f, "UtilizationMetricsDurationMaximum"),
            ExportableLambdaFunctionField::UtilizationMetricsMemoryAverage => write!(f, "UtilizationMetricsMemoryAverage"),
            ExportableLambdaFunctionField::UtilizationMetricsMemoryMaximum => write!(f, "UtilizationMetricsMemoryMaximum"),
            ExportableLambdaFunctionField::Unknown(value) => write!(f, "{}", value),
        }
    }
}
