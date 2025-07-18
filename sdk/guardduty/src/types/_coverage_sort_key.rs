// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `CoverageSortKey`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let coveragesortkey = unimplemented!();
/// match coveragesortkey {
///     CoverageSortKey::AccountId => { /* ... */ },
///     CoverageSortKey::AddonVersion => { /* ... */ },
///     CoverageSortKey::ClusterName => { /* ... */ },
///     CoverageSortKey::CoverageStatus => { /* ... */ },
///     CoverageSortKey::EcsClusterName => { /* ... */ },
///     CoverageSortKey::EksClusterName => { /* ... */ },
///     CoverageSortKey::InstanceId => { /* ... */ },
///     CoverageSortKey::Issue => { /* ... */ },
///     CoverageSortKey::UpdatedAt => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `coveragesortkey` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `CoverageSortKey::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `CoverageSortKey::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `CoverageSortKey::NewFeature` is defined.
/// Specifically, when `coveragesortkey` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `CoverageSortKey::NewFeature` also yielding `"NewFeature"`.
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
pub enum CoverageSortKey {
    #[allow(missing_docs)] // documentation missing in model
    AccountId,
    #[allow(missing_docs)] // documentation missing in model
    AddonVersion,
    #[allow(missing_docs)] // documentation missing in model
    ClusterName,
    #[allow(missing_docs)] // documentation missing in model
    CoverageStatus,
    #[allow(missing_docs)] // documentation missing in model
    EcsClusterName,
    #[allow(missing_docs)] // documentation missing in model
    EksClusterName,
    #[allow(missing_docs)] // documentation missing in model
    InstanceId,
    #[allow(missing_docs)] // documentation missing in model
    Issue,
    #[allow(missing_docs)] // documentation missing in model
    UpdatedAt,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for CoverageSortKey {
    fn from(s: &str) -> Self {
        match s {
            "ACCOUNT_ID" => CoverageSortKey::AccountId,
            "ADDON_VERSION" => CoverageSortKey::AddonVersion,
            "CLUSTER_NAME" => CoverageSortKey::ClusterName,
            "COVERAGE_STATUS" => CoverageSortKey::CoverageStatus,
            "ECS_CLUSTER_NAME" => CoverageSortKey::EcsClusterName,
            "EKS_CLUSTER_NAME" => CoverageSortKey::EksClusterName,
            "INSTANCE_ID" => CoverageSortKey::InstanceId,
            "ISSUE" => CoverageSortKey::Issue,
            "UPDATED_AT" => CoverageSortKey::UpdatedAt,
            other => CoverageSortKey::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for CoverageSortKey {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(CoverageSortKey::from(s))
    }
}
impl CoverageSortKey {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            CoverageSortKey::AccountId => "ACCOUNT_ID",
            CoverageSortKey::AddonVersion => "ADDON_VERSION",
            CoverageSortKey::ClusterName => "CLUSTER_NAME",
            CoverageSortKey::CoverageStatus => "COVERAGE_STATUS",
            CoverageSortKey::EcsClusterName => "ECS_CLUSTER_NAME",
            CoverageSortKey::EksClusterName => "EKS_CLUSTER_NAME",
            CoverageSortKey::InstanceId => "INSTANCE_ID",
            CoverageSortKey::Issue => "ISSUE",
            CoverageSortKey::UpdatedAt => "UPDATED_AT",
            CoverageSortKey::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACCOUNT_ID",
            "ADDON_VERSION",
            "CLUSTER_NAME",
            "COVERAGE_STATUS",
            "ECS_CLUSTER_NAME",
            "EKS_CLUSTER_NAME",
            "INSTANCE_ID",
            "ISSUE",
            "UPDATED_AT",
        ]
    }
}
impl ::std::convert::AsRef<str> for CoverageSortKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl CoverageSortKey {
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
impl ::std::fmt::Display for CoverageSortKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            CoverageSortKey::AccountId => write!(f, "ACCOUNT_ID"),
            CoverageSortKey::AddonVersion => write!(f, "ADDON_VERSION"),
            CoverageSortKey::ClusterName => write!(f, "CLUSTER_NAME"),
            CoverageSortKey::CoverageStatus => write!(f, "COVERAGE_STATUS"),
            CoverageSortKey::EcsClusterName => write!(f, "ECS_CLUSTER_NAME"),
            CoverageSortKey::EksClusterName => write!(f, "EKS_CLUSTER_NAME"),
            CoverageSortKey::InstanceId => write!(f, "INSTANCE_ID"),
            CoverageSortKey::Issue => write!(f, "ISSUE"),
            CoverageSortKey::UpdatedAt => write!(f, "UPDATED_AT"),
            CoverageSortKey::Unknown(value) => write!(f, "{}", value),
        }
    }
}
