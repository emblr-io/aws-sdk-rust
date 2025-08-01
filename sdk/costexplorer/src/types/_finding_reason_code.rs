// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `FindingReasonCode`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let findingreasoncode = unimplemented!();
/// match findingreasoncode {
///     FindingReasonCode::CpuOverProvisioned => { /* ... */ },
///     FindingReasonCode::CpuUnderProvisioned => { /* ... */ },
///     FindingReasonCode::DiskIopsOverProvisioned => { /* ... */ },
///     FindingReasonCode::DiskIopsUnderProvisioned => { /* ... */ },
///     FindingReasonCode::DiskThroughputOverProvisioned => { /* ... */ },
///     FindingReasonCode::DiskThroughputUnderProvisioned => { /* ... */ },
///     FindingReasonCode::EbsIopsOverProvisioned => { /* ... */ },
///     FindingReasonCode::EbsIopsUnderProvisioned => { /* ... */ },
///     FindingReasonCode::EbsThroughputOverProvisioned => { /* ... */ },
///     FindingReasonCode::EbsThroughputUnderProvisioned => { /* ... */ },
///     FindingReasonCode::MemoryOverProvisioned => { /* ... */ },
///     FindingReasonCode::MemoryUnderProvisioned => { /* ... */ },
///     FindingReasonCode::NetworkBandwidthOverProvisioned => { /* ... */ },
///     FindingReasonCode::NetworkBandwidthUnderProvisioned => { /* ... */ },
///     FindingReasonCode::NetworkPpsOverProvisioned => { /* ... */ },
///     FindingReasonCode::NetworkPpsUnderProvisioned => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `findingreasoncode` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `FindingReasonCode::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `FindingReasonCode::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `FindingReasonCode::NewFeature` is defined.
/// Specifically, when `findingreasoncode` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `FindingReasonCode::NewFeature` also yielding `"NewFeature"`.
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
pub enum FindingReasonCode {
    #[allow(missing_docs)] // documentation missing in model
    CpuOverProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    CpuUnderProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    DiskIopsOverProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    DiskIopsUnderProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    DiskThroughputOverProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    DiskThroughputUnderProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    EbsIopsOverProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    EbsIopsUnderProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    EbsThroughputOverProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    EbsThroughputUnderProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    MemoryOverProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    MemoryUnderProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    NetworkBandwidthOverProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    NetworkBandwidthUnderProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    NetworkPpsOverProvisioned,
    #[allow(missing_docs)] // documentation missing in model
    NetworkPpsUnderProvisioned,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for FindingReasonCode {
    fn from(s: &str) -> Self {
        match s {
            "CPU_OVER_PROVISIONED" => FindingReasonCode::CpuOverProvisioned,
            "CPU_UNDER_PROVISIONED" => FindingReasonCode::CpuUnderProvisioned,
            "DISK_IOPS_OVER_PROVISIONED" => FindingReasonCode::DiskIopsOverProvisioned,
            "DISK_IOPS_UNDER_PROVISIONED" => FindingReasonCode::DiskIopsUnderProvisioned,
            "DISK_THROUGHPUT_OVER_PROVISIONED" => FindingReasonCode::DiskThroughputOverProvisioned,
            "DISK_THROUGHPUT_UNDER_PROVISIONED" => FindingReasonCode::DiskThroughputUnderProvisioned,
            "EBS_IOPS_OVER_PROVISIONED" => FindingReasonCode::EbsIopsOverProvisioned,
            "EBS_IOPS_UNDER_PROVISIONED" => FindingReasonCode::EbsIopsUnderProvisioned,
            "EBS_THROUGHPUT_OVER_PROVISIONED" => FindingReasonCode::EbsThroughputOverProvisioned,
            "EBS_THROUGHPUT_UNDER_PROVISIONED" => FindingReasonCode::EbsThroughputUnderProvisioned,
            "MEMORY_OVER_PROVISIONED" => FindingReasonCode::MemoryOverProvisioned,
            "MEMORY_UNDER_PROVISIONED" => FindingReasonCode::MemoryUnderProvisioned,
            "NETWORK_BANDWIDTH_OVER_PROVISIONED" => FindingReasonCode::NetworkBandwidthOverProvisioned,
            "NETWORK_BANDWIDTH_UNDER_PROVISIONED" => FindingReasonCode::NetworkBandwidthUnderProvisioned,
            "NETWORK_PPS_OVER_PROVISIONED" => FindingReasonCode::NetworkPpsOverProvisioned,
            "NETWORK_PPS_UNDER_PROVISIONED" => FindingReasonCode::NetworkPpsUnderProvisioned,
            other => FindingReasonCode::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for FindingReasonCode {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(FindingReasonCode::from(s))
    }
}
impl FindingReasonCode {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            FindingReasonCode::CpuOverProvisioned => "CPU_OVER_PROVISIONED",
            FindingReasonCode::CpuUnderProvisioned => "CPU_UNDER_PROVISIONED",
            FindingReasonCode::DiskIopsOverProvisioned => "DISK_IOPS_OVER_PROVISIONED",
            FindingReasonCode::DiskIopsUnderProvisioned => "DISK_IOPS_UNDER_PROVISIONED",
            FindingReasonCode::DiskThroughputOverProvisioned => "DISK_THROUGHPUT_OVER_PROVISIONED",
            FindingReasonCode::DiskThroughputUnderProvisioned => "DISK_THROUGHPUT_UNDER_PROVISIONED",
            FindingReasonCode::EbsIopsOverProvisioned => "EBS_IOPS_OVER_PROVISIONED",
            FindingReasonCode::EbsIopsUnderProvisioned => "EBS_IOPS_UNDER_PROVISIONED",
            FindingReasonCode::EbsThroughputOverProvisioned => "EBS_THROUGHPUT_OVER_PROVISIONED",
            FindingReasonCode::EbsThroughputUnderProvisioned => "EBS_THROUGHPUT_UNDER_PROVISIONED",
            FindingReasonCode::MemoryOverProvisioned => "MEMORY_OVER_PROVISIONED",
            FindingReasonCode::MemoryUnderProvisioned => "MEMORY_UNDER_PROVISIONED",
            FindingReasonCode::NetworkBandwidthOverProvisioned => "NETWORK_BANDWIDTH_OVER_PROVISIONED",
            FindingReasonCode::NetworkBandwidthUnderProvisioned => "NETWORK_BANDWIDTH_UNDER_PROVISIONED",
            FindingReasonCode::NetworkPpsOverProvisioned => "NETWORK_PPS_OVER_PROVISIONED",
            FindingReasonCode::NetworkPpsUnderProvisioned => "NETWORK_PPS_UNDER_PROVISIONED",
            FindingReasonCode::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "CPU_OVER_PROVISIONED",
            "CPU_UNDER_PROVISIONED",
            "DISK_IOPS_OVER_PROVISIONED",
            "DISK_IOPS_UNDER_PROVISIONED",
            "DISK_THROUGHPUT_OVER_PROVISIONED",
            "DISK_THROUGHPUT_UNDER_PROVISIONED",
            "EBS_IOPS_OVER_PROVISIONED",
            "EBS_IOPS_UNDER_PROVISIONED",
            "EBS_THROUGHPUT_OVER_PROVISIONED",
            "EBS_THROUGHPUT_UNDER_PROVISIONED",
            "MEMORY_OVER_PROVISIONED",
            "MEMORY_UNDER_PROVISIONED",
            "NETWORK_BANDWIDTH_OVER_PROVISIONED",
            "NETWORK_BANDWIDTH_UNDER_PROVISIONED",
            "NETWORK_PPS_OVER_PROVISIONED",
            "NETWORK_PPS_UNDER_PROVISIONED",
        ]
    }
}
impl ::std::convert::AsRef<str> for FindingReasonCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl FindingReasonCode {
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
impl ::std::fmt::Display for FindingReasonCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            FindingReasonCode::CpuOverProvisioned => write!(f, "CPU_OVER_PROVISIONED"),
            FindingReasonCode::CpuUnderProvisioned => write!(f, "CPU_UNDER_PROVISIONED"),
            FindingReasonCode::DiskIopsOverProvisioned => write!(f, "DISK_IOPS_OVER_PROVISIONED"),
            FindingReasonCode::DiskIopsUnderProvisioned => write!(f, "DISK_IOPS_UNDER_PROVISIONED"),
            FindingReasonCode::DiskThroughputOverProvisioned => write!(f, "DISK_THROUGHPUT_OVER_PROVISIONED"),
            FindingReasonCode::DiskThroughputUnderProvisioned => write!(f, "DISK_THROUGHPUT_UNDER_PROVISIONED"),
            FindingReasonCode::EbsIopsOverProvisioned => write!(f, "EBS_IOPS_OVER_PROVISIONED"),
            FindingReasonCode::EbsIopsUnderProvisioned => write!(f, "EBS_IOPS_UNDER_PROVISIONED"),
            FindingReasonCode::EbsThroughputOverProvisioned => write!(f, "EBS_THROUGHPUT_OVER_PROVISIONED"),
            FindingReasonCode::EbsThroughputUnderProvisioned => write!(f, "EBS_THROUGHPUT_UNDER_PROVISIONED"),
            FindingReasonCode::MemoryOverProvisioned => write!(f, "MEMORY_OVER_PROVISIONED"),
            FindingReasonCode::MemoryUnderProvisioned => write!(f, "MEMORY_UNDER_PROVISIONED"),
            FindingReasonCode::NetworkBandwidthOverProvisioned => write!(f, "NETWORK_BANDWIDTH_OVER_PROVISIONED"),
            FindingReasonCode::NetworkBandwidthUnderProvisioned => write!(f, "NETWORK_BANDWIDTH_UNDER_PROVISIONED"),
            FindingReasonCode::NetworkPpsOverProvisioned => write!(f, "NETWORK_PPS_OVER_PROVISIONED"),
            FindingReasonCode::NetworkPpsUnderProvisioned => write!(f, "NETWORK_PPS_UNDER_PROVISIONED"),
            FindingReasonCode::Unknown(value) => write!(f, "{}", value),
        }
    }
}
