// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `FailbackReplicationError`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let failbackreplicationerror = unimplemented!();
/// match failbackreplicationerror {
///     FailbackReplicationError::AgentNotSeen => { /* ... */ },
///     FailbackReplicationError::FailbackClientNotSeen => { /* ... */ },
///     FailbackReplicationError::FailedGettingReplicationState => { /* ... */ },
///     FailbackReplicationError::FailedToAttachStagingDisks => { /* ... */ },
///     FailbackReplicationError::FailedToAuthenticateWithService => { /* ... */ },
///     FailbackReplicationError::FailedToBootReplicationServer => { /* ... */ },
///     FailbackReplicationError::FailedToConfigureReplicationSoftware => { /* ... */ },
///     FailbackReplicationError::FailedToConnectAgentToReplicationServer => { /* ... */ },
///     FailbackReplicationError::FailedToCreateSecurityGroup => { /* ... */ },
///     FailbackReplicationError::FailedToCreateStagingDisks => { /* ... */ },
///     FailbackReplicationError::FailedToDownloadReplicationSoftware => { /* ... */ },
///     FailbackReplicationError::FailedToDownloadReplicationSoftwareToFailbackClient => { /* ... */ },
///     FailbackReplicationError::FailedToEstablishAgentReplicatorSoftwareCommunication => { /* ... */ },
///     FailbackReplicationError::FailedToEstablishRecoveryInstanceCommunication => { /* ... */ },
///     FailbackReplicationError::FailedToLaunchReplicationServer => { /* ... */ },
///     FailbackReplicationError::FailedToPairAgentWithReplicationSoftware => { /* ... */ },
///     FailbackReplicationError::FailedToPairReplicationServerWithAgent => { /* ... */ },
///     FailbackReplicationError::FailedToStartDataTransfer => { /* ... */ },
///     FailbackReplicationError::NotConverging => { /* ... */ },
///     FailbackReplicationError::SnapshotsFailure => { /* ... */ },
///     FailbackReplicationError::UnstableNetwork => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `failbackreplicationerror` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `FailbackReplicationError::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `FailbackReplicationError::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `FailbackReplicationError::NewFeature` is defined.
/// Specifically, when `failbackreplicationerror` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `FailbackReplicationError::NewFeature` also yielding `"NewFeature"`.
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
pub enum FailbackReplicationError {
    #[allow(missing_docs)] // documentation missing in model
    AgentNotSeen,
    #[allow(missing_docs)] // documentation missing in model
    FailbackClientNotSeen,
    #[allow(missing_docs)] // documentation missing in model
    FailedGettingReplicationState,
    #[allow(missing_docs)] // documentation missing in model
    FailedToAttachStagingDisks,
    #[allow(missing_docs)] // documentation missing in model
    FailedToAuthenticateWithService,
    #[allow(missing_docs)] // documentation missing in model
    FailedToBootReplicationServer,
    #[allow(missing_docs)] // documentation missing in model
    FailedToConfigureReplicationSoftware,
    #[allow(missing_docs)] // documentation missing in model
    FailedToConnectAgentToReplicationServer,
    #[allow(missing_docs)] // documentation missing in model
    FailedToCreateSecurityGroup,
    #[allow(missing_docs)] // documentation missing in model
    FailedToCreateStagingDisks,
    #[allow(missing_docs)] // documentation missing in model
    FailedToDownloadReplicationSoftware,
    #[allow(missing_docs)] // documentation missing in model
    FailedToDownloadReplicationSoftwareToFailbackClient,
    #[allow(missing_docs)] // documentation missing in model
    FailedToEstablishAgentReplicatorSoftwareCommunication,
    #[allow(missing_docs)] // documentation missing in model
    FailedToEstablishRecoveryInstanceCommunication,
    #[allow(missing_docs)] // documentation missing in model
    FailedToLaunchReplicationServer,
    #[allow(missing_docs)] // documentation missing in model
    FailedToPairAgentWithReplicationSoftware,
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
impl ::std::convert::From<&str> for FailbackReplicationError {
    fn from(s: &str) -> Self {
        match s {
            "AGENT_NOT_SEEN" => FailbackReplicationError::AgentNotSeen,
            "FAILBACK_CLIENT_NOT_SEEN" => FailbackReplicationError::FailbackClientNotSeen,
            "FAILED_GETTING_REPLICATION_STATE" => FailbackReplicationError::FailedGettingReplicationState,
            "FAILED_TO_ATTACH_STAGING_DISKS" => FailbackReplicationError::FailedToAttachStagingDisks,
            "FAILED_TO_AUTHENTICATE_WITH_SERVICE" => FailbackReplicationError::FailedToAuthenticateWithService,
            "FAILED_TO_BOOT_REPLICATION_SERVER" => FailbackReplicationError::FailedToBootReplicationServer,
            "FAILED_TO_CONFIGURE_REPLICATION_SOFTWARE" => FailbackReplicationError::FailedToConfigureReplicationSoftware,
            "FAILED_TO_CONNECT_AGENT_TO_REPLICATION_SERVER" => FailbackReplicationError::FailedToConnectAgentToReplicationServer,
            "FAILED_TO_CREATE_SECURITY_GROUP" => FailbackReplicationError::FailedToCreateSecurityGroup,
            "FAILED_TO_CREATE_STAGING_DISKS" => FailbackReplicationError::FailedToCreateStagingDisks,
            "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE" => FailbackReplicationError::FailedToDownloadReplicationSoftware,
            "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE_TO_FAILBACK_CLIENT" => {
                FailbackReplicationError::FailedToDownloadReplicationSoftwareToFailbackClient
            }
            "FAILED_TO_ESTABLISH_AGENT_REPLICATOR_SOFTWARE_COMMUNICATION" => {
                FailbackReplicationError::FailedToEstablishAgentReplicatorSoftwareCommunication
            }
            "FAILED_TO_ESTABLISH_RECOVERY_INSTANCE_COMMUNICATION" => FailbackReplicationError::FailedToEstablishRecoveryInstanceCommunication,
            "FAILED_TO_LAUNCH_REPLICATION_SERVER" => FailbackReplicationError::FailedToLaunchReplicationServer,
            "FAILED_TO_PAIR_AGENT_WITH_REPLICATION_SOFTWARE" => FailbackReplicationError::FailedToPairAgentWithReplicationSoftware,
            "FAILED_TO_PAIR_REPLICATION_SERVER_WITH_AGENT" => FailbackReplicationError::FailedToPairReplicationServerWithAgent,
            "FAILED_TO_START_DATA_TRANSFER" => FailbackReplicationError::FailedToStartDataTransfer,
            "NOT_CONVERGING" => FailbackReplicationError::NotConverging,
            "SNAPSHOTS_FAILURE" => FailbackReplicationError::SnapshotsFailure,
            "UNSTABLE_NETWORK" => FailbackReplicationError::UnstableNetwork,
            other => FailbackReplicationError::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for FailbackReplicationError {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(FailbackReplicationError::from(s))
    }
}
impl FailbackReplicationError {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            FailbackReplicationError::AgentNotSeen => "AGENT_NOT_SEEN",
            FailbackReplicationError::FailbackClientNotSeen => "FAILBACK_CLIENT_NOT_SEEN",
            FailbackReplicationError::FailedGettingReplicationState => "FAILED_GETTING_REPLICATION_STATE",
            FailbackReplicationError::FailedToAttachStagingDisks => "FAILED_TO_ATTACH_STAGING_DISKS",
            FailbackReplicationError::FailedToAuthenticateWithService => "FAILED_TO_AUTHENTICATE_WITH_SERVICE",
            FailbackReplicationError::FailedToBootReplicationServer => "FAILED_TO_BOOT_REPLICATION_SERVER",
            FailbackReplicationError::FailedToConfigureReplicationSoftware => "FAILED_TO_CONFIGURE_REPLICATION_SOFTWARE",
            FailbackReplicationError::FailedToConnectAgentToReplicationServer => "FAILED_TO_CONNECT_AGENT_TO_REPLICATION_SERVER",
            FailbackReplicationError::FailedToCreateSecurityGroup => "FAILED_TO_CREATE_SECURITY_GROUP",
            FailbackReplicationError::FailedToCreateStagingDisks => "FAILED_TO_CREATE_STAGING_DISKS",
            FailbackReplicationError::FailedToDownloadReplicationSoftware => "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE",
            FailbackReplicationError::FailedToDownloadReplicationSoftwareToFailbackClient => {
                "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE_TO_FAILBACK_CLIENT"
            }
            FailbackReplicationError::FailedToEstablishAgentReplicatorSoftwareCommunication => {
                "FAILED_TO_ESTABLISH_AGENT_REPLICATOR_SOFTWARE_COMMUNICATION"
            }
            FailbackReplicationError::FailedToEstablishRecoveryInstanceCommunication => "FAILED_TO_ESTABLISH_RECOVERY_INSTANCE_COMMUNICATION",
            FailbackReplicationError::FailedToLaunchReplicationServer => "FAILED_TO_LAUNCH_REPLICATION_SERVER",
            FailbackReplicationError::FailedToPairAgentWithReplicationSoftware => "FAILED_TO_PAIR_AGENT_WITH_REPLICATION_SOFTWARE",
            FailbackReplicationError::FailedToPairReplicationServerWithAgent => "FAILED_TO_PAIR_REPLICATION_SERVER_WITH_AGENT",
            FailbackReplicationError::FailedToStartDataTransfer => "FAILED_TO_START_DATA_TRANSFER",
            FailbackReplicationError::NotConverging => "NOT_CONVERGING",
            FailbackReplicationError::SnapshotsFailure => "SNAPSHOTS_FAILURE",
            FailbackReplicationError::UnstableNetwork => "UNSTABLE_NETWORK",
            FailbackReplicationError::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AGENT_NOT_SEEN",
            "FAILBACK_CLIENT_NOT_SEEN",
            "FAILED_GETTING_REPLICATION_STATE",
            "FAILED_TO_ATTACH_STAGING_DISKS",
            "FAILED_TO_AUTHENTICATE_WITH_SERVICE",
            "FAILED_TO_BOOT_REPLICATION_SERVER",
            "FAILED_TO_CONFIGURE_REPLICATION_SOFTWARE",
            "FAILED_TO_CONNECT_AGENT_TO_REPLICATION_SERVER",
            "FAILED_TO_CREATE_SECURITY_GROUP",
            "FAILED_TO_CREATE_STAGING_DISKS",
            "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE",
            "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE_TO_FAILBACK_CLIENT",
            "FAILED_TO_ESTABLISH_AGENT_REPLICATOR_SOFTWARE_COMMUNICATION",
            "FAILED_TO_ESTABLISH_RECOVERY_INSTANCE_COMMUNICATION",
            "FAILED_TO_LAUNCH_REPLICATION_SERVER",
            "FAILED_TO_PAIR_AGENT_WITH_REPLICATION_SOFTWARE",
            "FAILED_TO_PAIR_REPLICATION_SERVER_WITH_AGENT",
            "FAILED_TO_START_DATA_TRANSFER",
            "NOT_CONVERGING",
            "SNAPSHOTS_FAILURE",
            "UNSTABLE_NETWORK",
        ]
    }
}
impl ::std::convert::AsRef<str> for FailbackReplicationError {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl FailbackReplicationError {
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
impl ::std::fmt::Display for FailbackReplicationError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            FailbackReplicationError::AgentNotSeen => write!(f, "AGENT_NOT_SEEN"),
            FailbackReplicationError::FailbackClientNotSeen => write!(f, "FAILBACK_CLIENT_NOT_SEEN"),
            FailbackReplicationError::FailedGettingReplicationState => write!(f, "FAILED_GETTING_REPLICATION_STATE"),
            FailbackReplicationError::FailedToAttachStagingDisks => write!(f, "FAILED_TO_ATTACH_STAGING_DISKS"),
            FailbackReplicationError::FailedToAuthenticateWithService => write!(f, "FAILED_TO_AUTHENTICATE_WITH_SERVICE"),
            FailbackReplicationError::FailedToBootReplicationServer => write!(f, "FAILED_TO_BOOT_REPLICATION_SERVER"),
            FailbackReplicationError::FailedToConfigureReplicationSoftware => write!(f, "FAILED_TO_CONFIGURE_REPLICATION_SOFTWARE"),
            FailbackReplicationError::FailedToConnectAgentToReplicationServer => write!(f, "FAILED_TO_CONNECT_AGENT_TO_REPLICATION_SERVER"),
            FailbackReplicationError::FailedToCreateSecurityGroup => write!(f, "FAILED_TO_CREATE_SECURITY_GROUP"),
            FailbackReplicationError::FailedToCreateStagingDisks => write!(f, "FAILED_TO_CREATE_STAGING_DISKS"),
            FailbackReplicationError::FailedToDownloadReplicationSoftware => write!(f, "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE"),
            FailbackReplicationError::FailedToDownloadReplicationSoftwareToFailbackClient => {
                write!(f, "FAILED_TO_DOWNLOAD_REPLICATION_SOFTWARE_TO_FAILBACK_CLIENT")
            }
            FailbackReplicationError::FailedToEstablishAgentReplicatorSoftwareCommunication => {
                write!(f, "FAILED_TO_ESTABLISH_AGENT_REPLICATOR_SOFTWARE_COMMUNICATION")
            }
            FailbackReplicationError::FailedToEstablishRecoveryInstanceCommunication => {
                write!(f, "FAILED_TO_ESTABLISH_RECOVERY_INSTANCE_COMMUNICATION")
            }
            FailbackReplicationError::FailedToLaunchReplicationServer => write!(f, "FAILED_TO_LAUNCH_REPLICATION_SERVER"),
            FailbackReplicationError::FailedToPairAgentWithReplicationSoftware => write!(f, "FAILED_TO_PAIR_AGENT_WITH_REPLICATION_SOFTWARE"),
            FailbackReplicationError::FailedToPairReplicationServerWithAgent => write!(f, "FAILED_TO_PAIR_REPLICATION_SERVER_WITH_AGENT"),
            FailbackReplicationError::FailedToStartDataTransfer => write!(f, "FAILED_TO_START_DATA_TRANSFER"),
            FailbackReplicationError::NotConverging => write!(f, "NOT_CONVERGING"),
            FailbackReplicationError::SnapshotsFailure => write!(f, "SNAPSHOTS_FAILURE"),
            FailbackReplicationError::UnstableNetwork => write!(f, "UNSTABLE_NETWORK"),
            FailbackReplicationError::Unknown(value) => write!(f, "{}", value),
        }
    }
}
