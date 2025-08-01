// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ExportableIdleField`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let exportableidlefield = unimplemented!();
/// match exportableidlefield {
///     ExportableIdleField::AccountId => { /* ... */ },
///     ExportableIdleField::Finding => { /* ... */ },
///     ExportableIdleField::FindingDescription => { /* ... */ },
///     ExportableIdleField::LastRefreshTimestamp => { /* ... */ },
///     ExportableIdleField::LookbackPeriodInDays => { /* ... */ },
///     ExportableIdleField::ResourceArn => { /* ... */ },
///     ExportableIdleField::ResourceId => { /* ... */ },
///     ExportableIdleField::ResourceType => { /* ... */ },
///     ExportableIdleField::SavingsOpportunity => { /* ... */ },
///     ExportableIdleField::SavingsOpportunityAfterDiscount => { /* ... */ },
///     ExportableIdleField::Tags => { /* ... */ },
///     ExportableIdleField::UtilizationMetricsCpuMaximum => { /* ... */ },
///     ExportableIdleField::UtilizationMetricsDatabaseConnectionsMaximum => { /* ... */ },
///     ExportableIdleField::UtilizationMetricsEbsVolumeReadIopsMaximum => { /* ... */ },
///     ExportableIdleField::UtilizationMetricsEbsVolumeWriteIopsMaximum => { /* ... */ },
///     ExportableIdleField::UtilizationMetricsMemoryMaximum => { /* ... */ },
///     ExportableIdleField::UtilizationMetricsNetworkInBytesPerSecondMaximum => { /* ... */ },
///     ExportableIdleField::UtilizationMetricsNetworkOutBytesPerSecondMaximum => { /* ... */ },
///     ExportableIdleField::UtilizationMetricsVolumeReadOpsPerSecondMaximum => { /* ... */ },
///     ExportableIdleField::UtilizationMetricsVolumeWriteOpsPerSecondMaximum => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `exportableidlefield` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ExportableIdleField::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ExportableIdleField::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ExportableIdleField::NewFeature` is defined.
/// Specifically, when `exportableidlefield` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ExportableIdleField::NewFeature` also yielding `"NewFeature"`.
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
pub enum ExportableIdleField {
    #[allow(missing_docs)] // documentation missing in model
    AccountId,
    #[allow(missing_docs)] // documentation missing in model
    Finding,
    #[allow(missing_docs)] // documentation missing in model
    FindingDescription,
    #[allow(missing_docs)] // documentation missing in model
    LastRefreshTimestamp,
    #[allow(missing_docs)] // documentation missing in model
    LookbackPeriodInDays,
    #[allow(missing_docs)] // documentation missing in model
    ResourceArn,
    #[allow(missing_docs)] // documentation missing in model
    ResourceId,
    #[allow(missing_docs)] // documentation missing in model
    ResourceType,
    #[allow(missing_docs)] // documentation missing in model
    SavingsOpportunity,
    #[allow(missing_docs)] // documentation missing in model
    SavingsOpportunityAfterDiscount,
    #[allow(missing_docs)] // documentation missing in model
    Tags,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsCpuMaximum,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsDatabaseConnectionsMaximum,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsEbsVolumeReadIopsMaximum,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsEbsVolumeWriteIopsMaximum,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsMemoryMaximum,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsNetworkInBytesPerSecondMaximum,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsNetworkOutBytesPerSecondMaximum,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsVolumeReadOpsPerSecondMaximum,
    #[allow(missing_docs)] // documentation missing in model
    UtilizationMetricsVolumeWriteOpsPerSecondMaximum,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ExportableIdleField {
    fn from(s: &str) -> Self {
        match s {
            "AccountId" => ExportableIdleField::AccountId,
            "Finding" => ExportableIdleField::Finding,
            "FindingDescription" => ExportableIdleField::FindingDescription,
            "LastRefreshTimestamp" => ExportableIdleField::LastRefreshTimestamp,
            "LookbackPeriodInDays" => ExportableIdleField::LookbackPeriodInDays,
            "ResourceArn" => ExportableIdleField::ResourceArn,
            "ResourceId" => ExportableIdleField::ResourceId,
            "ResourceType" => ExportableIdleField::ResourceType,
            "SavingsOpportunity" => ExportableIdleField::SavingsOpportunity,
            "SavingsOpportunityAfterDiscount" => ExportableIdleField::SavingsOpportunityAfterDiscount,
            "Tags" => ExportableIdleField::Tags,
            "UtilizationMetricsCpuMaximum" => ExportableIdleField::UtilizationMetricsCpuMaximum,
            "UtilizationMetricsDatabaseConnectionsMaximum" => ExportableIdleField::UtilizationMetricsDatabaseConnectionsMaximum,
            "UtilizationMetricsEBSVolumeReadIOPSMaximum" => ExportableIdleField::UtilizationMetricsEbsVolumeReadIopsMaximum,
            "UtilizationMetricsEBSVolumeWriteIOPSMaximum" => ExportableIdleField::UtilizationMetricsEbsVolumeWriteIopsMaximum,
            "UtilizationMetricsMemoryMaximum" => ExportableIdleField::UtilizationMetricsMemoryMaximum,
            "UtilizationMetricsNetworkInBytesPerSecondMaximum" => ExportableIdleField::UtilizationMetricsNetworkInBytesPerSecondMaximum,
            "UtilizationMetricsNetworkOutBytesPerSecondMaximum" => ExportableIdleField::UtilizationMetricsNetworkOutBytesPerSecondMaximum,
            "UtilizationMetricsVolumeReadOpsPerSecondMaximum" => ExportableIdleField::UtilizationMetricsVolumeReadOpsPerSecondMaximum,
            "UtilizationMetricsVolumeWriteOpsPerSecondMaximum" => ExportableIdleField::UtilizationMetricsVolumeWriteOpsPerSecondMaximum,
            other => ExportableIdleField::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ExportableIdleField {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ExportableIdleField::from(s))
    }
}
impl ExportableIdleField {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ExportableIdleField::AccountId => "AccountId",
            ExportableIdleField::Finding => "Finding",
            ExportableIdleField::FindingDescription => "FindingDescription",
            ExportableIdleField::LastRefreshTimestamp => "LastRefreshTimestamp",
            ExportableIdleField::LookbackPeriodInDays => "LookbackPeriodInDays",
            ExportableIdleField::ResourceArn => "ResourceArn",
            ExportableIdleField::ResourceId => "ResourceId",
            ExportableIdleField::ResourceType => "ResourceType",
            ExportableIdleField::SavingsOpportunity => "SavingsOpportunity",
            ExportableIdleField::SavingsOpportunityAfterDiscount => "SavingsOpportunityAfterDiscount",
            ExportableIdleField::Tags => "Tags",
            ExportableIdleField::UtilizationMetricsCpuMaximum => "UtilizationMetricsCpuMaximum",
            ExportableIdleField::UtilizationMetricsDatabaseConnectionsMaximum => "UtilizationMetricsDatabaseConnectionsMaximum",
            ExportableIdleField::UtilizationMetricsEbsVolumeReadIopsMaximum => "UtilizationMetricsEBSVolumeReadIOPSMaximum",
            ExportableIdleField::UtilizationMetricsEbsVolumeWriteIopsMaximum => "UtilizationMetricsEBSVolumeWriteIOPSMaximum",
            ExportableIdleField::UtilizationMetricsMemoryMaximum => "UtilizationMetricsMemoryMaximum",
            ExportableIdleField::UtilizationMetricsNetworkInBytesPerSecondMaximum => "UtilizationMetricsNetworkInBytesPerSecondMaximum",
            ExportableIdleField::UtilizationMetricsNetworkOutBytesPerSecondMaximum => "UtilizationMetricsNetworkOutBytesPerSecondMaximum",
            ExportableIdleField::UtilizationMetricsVolumeReadOpsPerSecondMaximum => "UtilizationMetricsVolumeReadOpsPerSecondMaximum",
            ExportableIdleField::UtilizationMetricsVolumeWriteOpsPerSecondMaximum => "UtilizationMetricsVolumeWriteOpsPerSecondMaximum",
            ExportableIdleField::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AccountId",
            "Finding",
            "FindingDescription",
            "LastRefreshTimestamp",
            "LookbackPeriodInDays",
            "ResourceArn",
            "ResourceId",
            "ResourceType",
            "SavingsOpportunity",
            "SavingsOpportunityAfterDiscount",
            "Tags",
            "UtilizationMetricsCpuMaximum",
            "UtilizationMetricsDatabaseConnectionsMaximum",
            "UtilizationMetricsEBSVolumeReadIOPSMaximum",
            "UtilizationMetricsEBSVolumeWriteIOPSMaximum",
            "UtilizationMetricsMemoryMaximum",
            "UtilizationMetricsNetworkInBytesPerSecondMaximum",
            "UtilizationMetricsNetworkOutBytesPerSecondMaximum",
            "UtilizationMetricsVolumeReadOpsPerSecondMaximum",
            "UtilizationMetricsVolumeWriteOpsPerSecondMaximum",
        ]
    }
}
impl ::std::convert::AsRef<str> for ExportableIdleField {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ExportableIdleField {
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
impl ::std::fmt::Display for ExportableIdleField {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ExportableIdleField::AccountId => write!(f, "AccountId"),
            ExportableIdleField::Finding => write!(f, "Finding"),
            ExportableIdleField::FindingDescription => write!(f, "FindingDescription"),
            ExportableIdleField::LastRefreshTimestamp => write!(f, "LastRefreshTimestamp"),
            ExportableIdleField::LookbackPeriodInDays => write!(f, "LookbackPeriodInDays"),
            ExportableIdleField::ResourceArn => write!(f, "ResourceArn"),
            ExportableIdleField::ResourceId => write!(f, "ResourceId"),
            ExportableIdleField::ResourceType => write!(f, "ResourceType"),
            ExportableIdleField::SavingsOpportunity => write!(f, "SavingsOpportunity"),
            ExportableIdleField::SavingsOpportunityAfterDiscount => write!(f, "SavingsOpportunityAfterDiscount"),
            ExportableIdleField::Tags => write!(f, "Tags"),
            ExportableIdleField::UtilizationMetricsCpuMaximum => write!(f, "UtilizationMetricsCpuMaximum"),
            ExportableIdleField::UtilizationMetricsDatabaseConnectionsMaximum => write!(f, "UtilizationMetricsDatabaseConnectionsMaximum"),
            ExportableIdleField::UtilizationMetricsEbsVolumeReadIopsMaximum => write!(f, "UtilizationMetricsEBSVolumeReadIOPSMaximum"),
            ExportableIdleField::UtilizationMetricsEbsVolumeWriteIopsMaximum => write!(f, "UtilizationMetricsEBSVolumeWriteIOPSMaximum"),
            ExportableIdleField::UtilizationMetricsMemoryMaximum => write!(f, "UtilizationMetricsMemoryMaximum"),
            ExportableIdleField::UtilizationMetricsNetworkInBytesPerSecondMaximum => write!(f, "UtilizationMetricsNetworkInBytesPerSecondMaximum"),
            ExportableIdleField::UtilizationMetricsNetworkOutBytesPerSecondMaximum => write!(f, "UtilizationMetricsNetworkOutBytesPerSecondMaximum"),
            ExportableIdleField::UtilizationMetricsVolumeReadOpsPerSecondMaximum => write!(f, "UtilizationMetricsVolumeReadOpsPerSecondMaximum"),
            ExportableIdleField::UtilizationMetricsVolumeWriteOpsPerSecondMaximum => write!(f, "UtilizationMetricsVolumeWriteOpsPerSecondMaximum"),
            ExportableIdleField::Unknown(value) => write!(f, "{}", value),
        }
    }
}
