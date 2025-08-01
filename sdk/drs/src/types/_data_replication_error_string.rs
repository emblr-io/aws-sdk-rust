// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `DataReplicationErrorString`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let datareplicationerrorstring = unimplemented!();
/// match datareplicationerrorstring {
///     DataReplicationErrorString::AgentNotSeen => { /* ... */ },
///     DataReplicationErrorString::FailedToAttachStagingDisks => { /* ... */ },
///     DataReplicationErrorString::FailedToAuthenticateWithService => { /* ... */ },
///     DataReplicationErrorString::FailedToBootReplicationServer => { /* ... */ },
///     DataReplicationErrorString::FailedToConnectAgentToReplicationServer => { /* ... */ },
///     DataReplicationErrorString::FailedToCreateSecurityGroup => { /* ... */ },
///     DataReplicationErrorString::FailedToCreateStagingDisks => { /* ... */ },
///     DataReplicationErrorString::FailedToDownloadReplicationSoftware => { /* ... */ },
///     DataReplicationErrorString::FailedToLaunchReplicationServer => { /* ... */ },
///     DataReplicationErrorString::FailedToPairReplicationServerWithAgent => { /* ... */ },
///     DataReplicationErrorString::FailedToStartDataTransfer => { /* ... */ },
///     DataReplicationErrorString::NotConverging => { /* ... */ },
///     DataReplicationErrorString::SnapshotsFailure => { /* ... */ },
///     DataReplicationErrorString::UnstableNetwork => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `datareplicationerrorstring` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `DataReplicationErrorString::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `DataReplicationErrorString::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `DataReplicationErrorString::NewFeature` is defined.
/// Specifically, when `datareplicationerrorstring` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `DataReplicationErrorString::NewFeature` also yielding `"NewFeature"`.
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
pub enum DataReplicationErrorString {
    #[allow(missing_docs)] // documentation missing in model
    AgentNotSeen,
    #[allow(missing_docs)] // documentation missing in model
    FailedToAttachStagingDisks,
    #[allow(missing_docs)] // documentation missing in model
    FailedToAuthenticateWithService,
    #[allow(missing_docs)] // documentation missing in model
    FailedToBootReplicationServer,
    #[allow(missing_docs)] // documentation missing in model
    FailedToConnectAgentToReplicationServer,
    #[allow(missing_docs)] // documentation missing in model
    FailedToCreateSecurityGroup,
    #[allow(missing_docs)] // documentation missing in model
    FailedToCreateStagingDisks,
    #[allow(missing_docs)] // documentation missing in model
    FailedToDownloadReplicationSoftware,
    #[allow(missing_docs)] // documentation missing in model
    FailedToLaunchReplicationServer,
    #[allow(missing_docs)] // documentation missing in model
    FailedToPairReplicationServerWithAgent,
    #[allow(missing_docs)] // documentation missing in model
    FailedToStartDataTransfer,
    #[allow(missing_docs)] // documentation missing in model
    NotConverging,
    #[allow(missing_docs)] // documentation missing in model
    SnapshotsFailure,
    #[allow(missing_docs)] // documentation missing in model
    UnstableNetwork,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for DataReplicationErrorString {
    fn from(s: &str) -> Self {
        match s {
            "AGENT_NOT_SEEN" => DataReplicationErrorString::AgentNotSeen,
            "FAILED_TO_ATTACH_STAGING_DISKS" => DataReplicationErrorString::FailedToAttachStagingDisks,
            "FAILED_TO_AUTHENTICATE_WITH_SERVICE" => DataReplicationErrorString::FailedToAuthenticateWithService,
            "FAILED_TO_BOOT_REPLICATION_SERVER" => DataReplicationErrorString::FailedToBootReplicationServer,
            "FAILED_TO_CONNECT_AGENT_TO_REPLICATION_SERVER" => DataReplicationErrorString::FailedToConnectAgentToReplicationServer,
            "FAILED_TO_CREATE_SECURITY_GROUP" => DataReplicationErrorString::FailedToCreateSecurityGroup,
            "FAILED_TO_CREATE_STAGING_DISKS" => DataReplicationErrorString::FailedToCreateStagingDisks,
            "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE" => DataReplicationErrorString::FailedToDownloadReplicationSoftware,
            "FAILED_TO_LAUNCH_REPLICATION_SERVER" => DataReplicationErrorString::FailedToLaunchReplicationServer,
            "FAILED_TO_PAIR_REPLICATION_SERVER_WITH_AGENT" => DataReplicationErrorString::FailedToPairReplicationServerWithAgent,
            "FAILED_TO_START_DATA_TRANSFER" => DataReplicationErrorString::FailedToStartDataTransfer,
            "NOT_CONVERGING" => DataReplicationErrorString::NotConverging,
            "SNAPSHOTS_FAILURE" => DataReplicationErrorString::SnapshotsFailure,
            "UNSTABLE_NETWORK" => DataReplicationErrorString::UnstableNetwork,
            other => DataReplicationErrorString::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for DataReplicationErrorString {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(DataReplicationErrorString::from(s))
    }
}
impl DataReplicationErrorString {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            DataReplicationErrorString::AgentNotSeen => "AGENT_NOT_SEEN",
            DataReplicationErrorString::FailedToAttachStagingDisks => "FAILED_TO_ATTACH_STAGING_DISKS",
            DataReplicationErrorString::FailedToAuthenticateWithService => "FAILED_TO_AUTHENTICATE_WITH_SERVICE",
            DataReplicationErrorString::FailedToBootReplicationServer => "FAILED_TO_BOOT_REPLICATION_SERVER",
            DataReplicationErrorString::FailedToConnectAgentToReplicationServer => "FAILED_TO_CONNECT_AGENT_TO_REPLICATION_SERVER",
            DataReplicationErrorString::FailedToCreateSecurityGroup => "FAILED_TO_CREATE_SECURITY_GROUP",
            DataReplicationErrorString::FailedToCreateStagingDisks => "FAILED_TO_CREATE_STAGING_DISKS",
            DataReplicationErrorString::FailedToDownloadReplicationSoftware => "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE",
            DataReplicationErrorString::FailedToLaunchReplicationServer => "FAILED_TO_LAUNCH_REPLICATION_SERVER",
            DataReplicationErrorString::FailedToPairReplicationServerWithAgent => "FAILED_TO_PAIR_REPLICATION_SERVER_WITH_AGENT",
            DataReplicationErrorString::FailedToStartDataTransfer => "FAILED_TO_START_DATA_TRANSFER",
            DataReplicationErrorString::NotConverging => "NOT_CONVERGING",
            DataReplicationErrorString::SnapshotsFailure => "SNAPSHOTS_FAILURE",
            DataReplicationErrorString::UnstableNetwork => "UNSTABLE_NETWORK",
            DataReplicationErrorString::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AGENT_NOT_SEEN",
            "FAILED_TO_ATTACH_STAGING_DISKS",
            "FAILED_TO_AUTHENTICATE_WITH_SERVICE",
            "FAILED_TO_BOOT_REPLICATION_SERVER",
            "FAILED_TO_CONNECT_AGENT_TO_REPLICATION_SERVER",
            "FAILED_TO_CREATE_SECURITY_GROUP",
            "FAILED_TO_CREATE_STAGING_DISKS",
            "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE",
            "FAILED_TO_LAUNCH_REPLICATION_SERVER",
            "FAILED_TO_PAIR_REPLICATION_SERVER_WITH_AGENT",
            "FAILED_TO_START_DATA_TRANSFER",
            "NOT_CONVERGING",
            "SNAPSHOTS_FAILURE",
            "UNSTABLE_NETWORK",
        ]
    }
}
impl ::std::convert::AsRef<str> for DataReplicationErrorString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl DataReplicationErrorString {
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
impl ::std::fmt::Display for DataReplicationErrorString {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            DataReplicationErrorString::AgentNotSeen => write!(f, "AGENT_NOT_SEEN"),
            DataReplicationErrorString::FailedToAttachStagingDisks => write!(f, "FAILED_TO_ATTACH_STAGING_DISKS"),
            DataReplicationErrorString::FailedToAuthenticateWithService => write!(f, "FAILED_TO_AUTHENTICATE_WITH_SERVICE"),
            DataReplicationErrorString::FailedToBootReplicationServer => write!(f, "FAILED_TO_BOOT_REPLICATION_SERVER"),
            DataReplicationErrorString::FailedToConnectAgentToReplicationServer => write!(f, "FAILED_TO_CONNECT_AGENT_TO_REPLICATION_SERVER"),
            DataReplicationErrorString::FailedToCreateSecurityGroup => write!(f, "FAILED_TO_CREATE_SECURITY_GROUP"),
            DataReplicationErrorString::FailedToCreateStagingDisks => write!(f, "FAILED_TO_CREATE_STAGING_DISKS"),
            DataReplicationErrorString::FailedToDownloadReplicationSoftware => write!(f, "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE"),
            DataReplicationErrorString::FailedToLaunchReplicationServer => write!(f, "FAILED_TO_LAUNCH_REPLICATION_SERVER"),
            DataReplicationErrorString::FailedToPairReplicationServerWithAgent => write!(f, "FAILED_TO_PAIR_REPLICATION_SERVER_WITH_AGENT"),
            DataReplicationErrorString::FailedToStartDataTransfer => write!(f, "FAILED_TO_START_DATA_TRANSFER"),
            DataReplicationErrorString::NotConverging => write!(f, "NOT_CONVERGING"),
            DataReplicationErrorString::SnapshotsFailure => write!(f, "SNAPSHOTS_FAILURE"),
            DataReplicationErrorString::UnstableNetwork => write!(f, "UNSTABLE_NETWORK"),
            DataReplicationErrorString::Unknown(value) => write!(f, "{}", value),
        }
    }
}
