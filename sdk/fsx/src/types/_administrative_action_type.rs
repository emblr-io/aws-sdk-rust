// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AdministrativeActionType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let administrativeactiontype = unimplemented!();
/// match administrativeactiontype {
///     AdministrativeActionType::DownloadDataFromBackup => { /* ... */ },
///     AdministrativeActionType::FileSystemAliasAssociation => { /* ... */ },
///     AdministrativeActionType::FileSystemAliasDisassociation => { /* ... */ },
///     AdministrativeActionType::FileSystemUpdate => { /* ... */ },
///     AdministrativeActionType::IopsOptimization => { /* ... */ },
///     AdministrativeActionType::MisconfiguredStateRecovery => { /* ... */ },
///     AdministrativeActionType::ReleaseNfsV3Locks => { /* ... */ },
///     AdministrativeActionType::SnapshotUpdate => { /* ... */ },
///     AdministrativeActionType::StorageOptimization => { /* ... */ },
///     AdministrativeActionType::StorageTypeOptimization => { /* ... */ },
///     AdministrativeActionType::ThroughputOptimization => { /* ... */ },
///     AdministrativeActionType::VolumeInitializeWithSnapshot => { /* ... */ },
///     AdministrativeActionType::VolumeRestore => { /* ... */ },
///     AdministrativeActionType::VolumeUpdate => { /* ... */ },
///     AdministrativeActionType::VolumeUpdateWithSnapshot => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `administrativeactiontype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AdministrativeActionType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AdministrativeActionType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AdministrativeActionType::NewFeature` is defined.
/// Specifically, when `administrativeactiontype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AdministrativeActionType::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// <p>Describes the type of administrative action, as follows:</p>
/// <ul>
/// <li>
/// <p>
/// <code>FILE_SYSTEM_UPDATE</code> - A file system update administrative action
/// initiated from the Amazon FSx console, API
/// (<code>UpdateFileSystem</code>), or CLI
/// (<code>update-file-system</code>).</p>
/// </li>
/// <li>
/// <p>
/// <code>THROUGHPUT_OPTIMIZATION</code> - After the <code>FILE_SYSTEM_UPDATE</code>
/// task to increase a file system's throughput capacity has been completed
/// successfully, a <code>THROUGHPUT_OPTIMIZATION</code> task starts.</p>
/// <p>You can track the storage-optimization progress using the
/// <code>ProgressPercent</code> property. When
/// <code>THROUGHPUT_OPTIMIZATION</code> has been completed successfully, the
/// parent <code>FILE_SYSTEM_UPDATE</code> action status changes to
/// <code>COMPLETED</code>. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/WindowsGuide/managing-throughput-capacity.html">Managing
/// throughput capacity</a> in the <i>Amazon FSx for Windows
/// File Server User Guide</i>.</p>
/// </li>
/// <li>
/// <p>
/// <code>STORAGE_OPTIMIZATION</code> - After the <code>FILE_SYSTEM_UPDATE</code>
/// task to increase a file system's storage capacity has completed
/// successfully, a <code>STORAGE_OPTIMIZATION</code> task starts. </p>
/// <ul>
/// <li>
/// <p>For Windows and ONTAP, storage optimization is the process of migrating the file system data
/// to newer larger disks.</p>
/// </li>
/// <li>
/// <p>For Lustre, storage optimization consists of rebalancing the data across the existing and
/// newly added file servers.</p>
/// </li>
/// </ul>
/// <p>You can track the storage-optimization progress using the
/// <code>ProgressPercent</code> property. When
/// <code>STORAGE_OPTIMIZATION</code> has been completed successfully, the
/// parent <code>FILE_SYSTEM_UPDATE</code> action status changes to
/// <code>COMPLETED</code>. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/WindowsGuide/managing-storage-capacity.html">Managing
/// storage capacity</a> in the <i>Amazon FSx for Windows
/// File Server User Guide</i>, <a href="https://docs.aws.amazon.com/fsx/latest/LustreGuide/managing-storage-capacity.html">Managing storage
/// capacity</a> in the <i>Amazon FSx for
/// Lustre User Guide</i>, and
/// <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/managing-storage-capacity.html">Managing storage capacity and provisioned IOPS</a> in the <i>Amazon FSx for NetApp ONTAP User
/// Guide</i>.</p>
/// </li>
/// <li>
/// <p>
/// <code>FILE_SYSTEM_ALIAS_ASSOCIATION</code> - A file system update to associate a new Domain
/// Name System (DNS) alias with the file system. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/APIReference/API_AssociateFileSystemAliases.html">
/// AssociateFileSystemAliases</a>.</p>
/// </li>
/// <li>
/// <p>
/// <code>FILE_SYSTEM_ALIAS_DISASSOCIATION</code> - A file system update to disassociate a DNS alias from the file system.
/// For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/APIReference/API_DisassociateFileSystemAliases.html">DisassociateFileSystemAliases</a>.</p>
/// </li>
/// <li>
/// <p>
/// <code>IOPS_OPTIMIZATION</code> - After the <code>FILE_SYSTEM_UPDATE</code>
/// task to increase a file system's throughput capacity has been completed
/// successfully, a <code>IOPS_OPTIMIZATION</code> task starts.</p>
/// <p>You can track the storage-optimization progress using the
/// <code>ProgressPercent</code> property. When <code>IOPS_OPTIMIZATION</code>
/// has been completed successfully, the parent <code>FILE_SYSTEM_UPDATE</code>
/// action status changes to <code>COMPLETED</code>. For more information, see
/// <a href="https://docs.aws.amazon.com/fsx/latest/WindowsGuide/managing-provisioned-ssd-iops.html">Managing
/// provisioned SSD IOPS</a> in the Amazon FSx for Windows File
/// Server User Guide.</p>
/// </li>
/// <li>
/// <p>
/// <code>STORAGE_TYPE_OPTIMIZATION</code> - After the <code>FILE_SYSTEM_UPDATE</code>
/// task to increase a file system's throughput capacity has been completed
/// successfully, a <code>STORAGE_TYPE_OPTIMIZATION</code> task starts.</p>
/// <p>You can track the storage-optimization progress using the
/// <code>ProgressPercent</code> property. When
/// <code>STORAGE_TYPE_OPTIMIZATION</code> has been completed successfully, the
/// parent <code>FILE_SYSTEM_UPDATE</code> action status changes to
/// <code>COMPLETED</code>.</p>
/// </li>
/// <li>
/// <p>
/// <code>VOLUME_UPDATE</code> - A volume update to an Amazon FSx for OpenZFS volume
/// initiated from the Amazon FSx console, API (<code>UpdateVolume</code>),
/// or CLI (<code>update-volume</code>).</p>
/// </li>
/// <li>
/// <p>
/// <code>VOLUME_RESTORE</code> - An Amazon FSx for OpenZFS volume
/// is returned to the state saved by the specified snapshot, initiated from an
/// API (<code>RestoreVolumeFromSnapshot</code>) or CLI
/// (<code>restore-volume-from-snapshot</code>).</p>
/// </li>
/// <li>
/// <p>
/// <code>SNAPSHOT_UPDATE</code> - A snapshot update to an Amazon FSx for
/// OpenZFS volume initiated from the Amazon FSx console, API
/// (<code>UpdateSnapshot</code>), or CLI (<code>update-snapshot</code>).</p>
/// </li>
/// <li>
/// <p>
/// <code>RELEASE_NFS_V3_LOCKS</code> - Tracks the release of Network File System
/// (NFS) V3 locks on an Amazon FSx for OpenZFS file system.</p>
/// </li>
/// <li>
/// <p>
/// <code>DOWNLOAD_DATA_FROM_BACKUP</code> - An FSx for ONTAP backup is
/// being restored to a new volume on a second-generation file system. Once the all the file
/// metadata is loaded onto the volume, you can mount the volume with read-only access.
/// during this process.</p>
/// </li>
/// <li>
/// <p>
/// <code>VOLUME_INITIALIZE_WITH_SNAPSHOT</code> - A volume is being created from
/// a snapshot on a different FSx for OpenZFS file system. You can
/// initiate this from the Amazon FSx console, API
/// (<code>CreateVolume</code>), or CLI (<code>create-volume</code>) when using
/// the using the <code>FULL_COPY</code> strategy.</p>
/// </li>
/// <li>
/// <p>
/// <code>VOLUME_UPDATE_WITH_SNAPSHOT</code> - A volume is being updated from a
/// snapshot on a different FSx for OpenZFS file system. You can initiate
/// this from the Amazon FSx console, API
/// (<code>CopySnapshotAndUpdateVolume</code>), or CLI
/// (<code>copy-snapshot-and-update-volume</code>).</p>
/// </li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum AdministrativeActionType {
    #[allow(missing_docs)] // documentation missing in model
    DownloadDataFromBackup,
    #[allow(missing_docs)] // documentation missing in model
    FileSystemAliasAssociation,
    #[allow(missing_docs)] // documentation missing in model
    FileSystemAliasDisassociation,
    #[allow(missing_docs)] // documentation missing in model
    FileSystemUpdate,
    #[allow(missing_docs)] // documentation missing in model
    IopsOptimization,
    #[allow(missing_docs)] // documentation missing in model
    MisconfiguredStateRecovery,
    #[allow(missing_docs)] // documentation missing in model
    ReleaseNfsV3Locks,
    #[allow(missing_docs)] // documentation missing in model
    SnapshotUpdate,
    #[allow(missing_docs)] // documentation missing in model
    StorageOptimization,
    #[allow(missing_docs)] // documentation missing in model
    StorageTypeOptimization,
    #[allow(missing_docs)] // documentation missing in model
    ThroughputOptimization,
    #[allow(missing_docs)] // documentation missing in model
    VolumeInitializeWithSnapshot,
    #[allow(missing_docs)] // documentation missing in model
    VolumeRestore,
    #[allow(missing_docs)] // documentation missing in model
    VolumeUpdate,
    #[allow(missing_docs)] // documentation missing in model
    VolumeUpdateWithSnapshot,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AdministrativeActionType {
    fn from(s: &str) -> Self {
        match s {
            "DOWNLOAD_DATA_FROM_BACKUP" => AdministrativeActionType::DownloadDataFromBackup,
            "FILE_SYSTEM_ALIAS_ASSOCIATION" => AdministrativeActionType::FileSystemAliasAssociation,
            "FILE_SYSTEM_ALIAS_DISASSOCIATION" => AdministrativeActionType::FileSystemAliasDisassociation,
            "FILE_SYSTEM_UPDATE" => AdministrativeActionType::FileSystemUpdate,
            "IOPS_OPTIMIZATION" => AdministrativeActionType::IopsOptimization,
            "MISCONFIGURED_STATE_RECOVERY" => AdministrativeActionType::MisconfiguredStateRecovery,
            "RELEASE_NFS_V3_LOCKS" => AdministrativeActionType::ReleaseNfsV3Locks,
            "SNAPSHOT_UPDATE" => AdministrativeActionType::SnapshotUpdate,
            "STORAGE_OPTIMIZATION" => AdministrativeActionType::StorageOptimization,
            "STORAGE_TYPE_OPTIMIZATION" => AdministrativeActionType::StorageTypeOptimization,
            "THROUGHPUT_OPTIMIZATION" => AdministrativeActionType::ThroughputOptimization,
            "VOLUME_INITIALIZE_WITH_SNAPSHOT" => AdministrativeActionType::VolumeInitializeWithSnapshot,
            "VOLUME_RESTORE" => AdministrativeActionType::VolumeRestore,
            "VOLUME_UPDATE" => AdministrativeActionType::VolumeUpdate,
            "VOLUME_UPDATE_WITH_SNAPSHOT" => AdministrativeActionType::VolumeUpdateWithSnapshot,
            other => AdministrativeActionType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AdministrativeActionType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AdministrativeActionType::from(s))
    }
}
impl AdministrativeActionType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AdministrativeActionType::DownloadDataFromBackup => "DOWNLOAD_DATA_FROM_BACKUP",
            AdministrativeActionType::FileSystemAliasAssociation => "FILE_SYSTEM_ALIAS_ASSOCIATION",
            AdministrativeActionType::FileSystemAliasDisassociation => "FILE_SYSTEM_ALIAS_DISASSOCIATION",
            AdministrativeActionType::FileSystemUpdate => "FILE_SYSTEM_UPDATE",
            AdministrativeActionType::IopsOptimization => "IOPS_OPTIMIZATION",
            AdministrativeActionType::MisconfiguredStateRecovery => "MISCONFIGURED_STATE_RECOVERY",
            AdministrativeActionType::ReleaseNfsV3Locks => "RELEASE_NFS_V3_LOCKS",
            AdministrativeActionType::SnapshotUpdate => "SNAPSHOT_UPDATE",
            AdministrativeActionType::StorageOptimization => "STORAGE_OPTIMIZATION",
            AdministrativeActionType::StorageTypeOptimization => "STORAGE_TYPE_OPTIMIZATION",
            AdministrativeActionType::ThroughputOptimization => "THROUGHPUT_OPTIMIZATION",
            AdministrativeActionType::VolumeInitializeWithSnapshot => "VOLUME_INITIALIZE_WITH_SNAPSHOT",
            AdministrativeActionType::VolumeRestore => "VOLUME_RESTORE",
            AdministrativeActionType::VolumeUpdate => "VOLUME_UPDATE",
            AdministrativeActionType::VolumeUpdateWithSnapshot => "VOLUME_UPDATE_WITH_SNAPSHOT",
            AdministrativeActionType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "DOWNLOAD_DATA_FROM_BACKUP",
            "FILE_SYSTEM_ALIAS_ASSOCIATION",
            "FILE_SYSTEM_ALIAS_DISASSOCIATION",
            "FILE_SYSTEM_UPDATE",
            "IOPS_OPTIMIZATION",
            "MISCONFIGURED_STATE_RECOVERY",
            "RELEASE_NFS_V3_LOCKS",
            "SNAPSHOT_UPDATE",
            "STORAGE_OPTIMIZATION",
            "STORAGE_TYPE_OPTIMIZATION",
            "THROUGHPUT_OPTIMIZATION",
            "VOLUME_INITIALIZE_WITH_SNAPSHOT",
            "VOLUME_RESTORE",
            "VOLUME_UPDATE",
            "VOLUME_UPDATE_WITH_SNAPSHOT",
        ]
    }
}
impl ::std::convert::AsRef<str> for AdministrativeActionType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AdministrativeActionType {
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
impl ::std::fmt::Display for AdministrativeActionType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AdministrativeActionType::DownloadDataFromBackup => write!(f, "DOWNLOAD_DATA_FROM_BACKUP"),
            AdministrativeActionType::FileSystemAliasAssociation => write!(f, "FILE_SYSTEM_ALIAS_ASSOCIATION"),
            AdministrativeActionType::FileSystemAliasDisassociation => write!(f, "FILE_SYSTEM_ALIAS_DISASSOCIATION"),
            AdministrativeActionType::FileSystemUpdate => write!(f, "FILE_SYSTEM_UPDATE"),
            AdministrativeActionType::IopsOptimization => write!(f, "IOPS_OPTIMIZATION"),
            AdministrativeActionType::MisconfiguredStateRecovery => write!(f, "MISCONFIGURED_STATE_RECOVERY"),
            AdministrativeActionType::ReleaseNfsV3Locks => write!(f, "RELEASE_NFS_V3_LOCKS"),
            AdministrativeActionType::SnapshotUpdate => write!(f, "SNAPSHOT_UPDATE"),
            AdministrativeActionType::StorageOptimization => write!(f, "STORAGE_OPTIMIZATION"),
            AdministrativeActionType::StorageTypeOptimization => write!(f, "STORAGE_TYPE_OPTIMIZATION"),
            AdministrativeActionType::ThroughputOptimization => write!(f, "THROUGHPUT_OPTIMIZATION"),
            AdministrativeActionType::VolumeInitializeWithSnapshot => write!(f, "VOLUME_INITIALIZE_WITH_SNAPSHOT"),
            AdministrativeActionType::VolumeRestore => write!(f, "VOLUME_RESTORE"),
            AdministrativeActionType::VolumeUpdate => write!(f, "VOLUME_UPDATE"),
            AdministrativeActionType::VolumeUpdateWithSnapshot => write!(f, "VOLUME_UPDATE_WITH_SNAPSHOT"),
            AdministrativeActionType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
