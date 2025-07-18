// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `WorkspaceStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let workspacestatus = unimplemented!();
/// match workspacestatus {
///     WorkspaceStatus::Active => { /* ... */ },
///     WorkspaceStatus::Creating => { /* ... */ },
///     WorkspaceStatus::CreationFailed => { /* ... */ },
///     WorkspaceStatus::Deleting => { /* ... */ },
///     WorkspaceStatus::DeletionFailed => { /* ... */ },
///     WorkspaceStatus::Failed => { /* ... */ },
///     WorkspaceStatus::LicenseRemovalFailed => { /* ... */ },
///     WorkspaceStatus::UpdateFailed => { /* ... */ },
///     WorkspaceStatus::Updating => { /* ... */ },
///     WorkspaceStatus::UpgradeFailed => { /* ... */ },
///     WorkspaceStatus::Upgrading => { /* ... */ },
///     WorkspaceStatus::VersionUpdateFailed => { /* ... */ },
///     WorkspaceStatus::VersionUpdating => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `workspacestatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `WorkspaceStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `WorkspaceStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `WorkspaceStatus::NewFeature` is defined.
/// Specifically, when `workspacestatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `WorkspaceStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum WorkspaceStatus {
    /// Workspace is active.
    Active,
    /// Workspace is being created.
    Creating,
    /// Workspace creation failed.
    CreationFailed,
    /// Workspace is being deleted.
    Deleting,
    /// Workspace deletion failed.
    DeletionFailed,
    /// Workspace is in an invalid state, it can only and should be deleted.
    Failed,
    /// Failed to remove enterprise license from workspace.
    LicenseRemovalFailed,
    /// Workspace update failed.
    UpdateFailed,
    /// Workspace is being updated.
    Updating,
    /// Workspace upgrade failed.
    UpgradeFailed,
    /// Workspace is being upgraded to enterprise.
    Upgrading,
    /// Workspace version update failed.
    VersionUpdateFailed,
    /// Workspace version is being updated.
    VersionUpdating,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for WorkspaceStatus {
    fn from(s: &str) -> Self {
        match s {
            "ACTIVE" => WorkspaceStatus::Active,
            "CREATING" => WorkspaceStatus::Creating,
            "CREATION_FAILED" => WorkspaceStatus::CreationFailed,
            "DELETING" => WorkspaceStatus::Deleting,
            "DELETION_FAILED" => WorkspaceStatus::DeletionFailed,
            "FAILED" => WorkspaceStatus::Failed,
            "LICENSE_REMOVAL_FAILED" => WorkspaceStatus::LicenseRemovalFailed,
            "UPDATE_FAILED" => WorkspaceStatus::UpdateFailed,
            "UPDATING" => WorkspaceStatus::Updating,
            "UPGRADE_FAILED" => WorkspaceStatus::UpgradeFailed,
            "UPGRADING" => WorkspaceStatus::Upgrading,
            "VERSION_UPDATE_FAILED" => WorkspaceStatus::VersionUpdateFailed,
            "VERSION_UPDATING" => WorkspaceStatus::VersionUpdating,
            other => WorkspaceStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for WorkspaceStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(WorkspaceStatus::from(s))
    }
}
impl WorkspaceStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            WorkspaceStatus::Active => "ACTIVE",
            WorkspaceStatus::Creating => "CREATING",
            WorkspaceStatus::CreationFailed => "CREATION_FAILED",
            WorkspaceStatus::Deleting => "DELETING",
            WorkspaceStatus::DeletionFailed => "DELETION_FAILED",
            WorkspaceStatus::Failed => "FAILED",
            WorkspaceStatus::LicenseRemovalFailed => "LICENSE_REMOVAL_FAILED",
            WorkspaceStatus::UpdateFailed => "UPDATE_FAILED",
            WorkspaceStatus::Updating => "UPDATING",
            WorkspaceStatus::UpgradeFailed => "UPGRADE_FAILED",
            WorkspaceStatus::Upgrading => "UPGRADING",
            WorkspaceStatus::VersionUpdateFailed => "VERSION_UPDATE_FAILED",
            WorkspaceStatus::VersionUpdating => "VERSION_UPDATING",
            WorkspaceStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACTIVE",
            "CREATING",
            "CREATION_FAILED",
            "DELETING",
            "DELETION_FAILED",
            "FAILED",
            "LICENSE_REMOVAL_FAILED",
            "UPDATE_FAILED",
            "UPDATING",
            "UPGRADE_FAILED",
            "UPGRADING",
            "VERSION_UPDATE_FAILED",
            "VERSION_UPDATING",
        ]
    }
}
impl ::std::convert::AsRef<str> for WorkspaceStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl WorkspaceStatus {
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
impl ::std::fmt::Display for WorkspaceStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            WorkspaceStatus::Active => write!(f, "ACTIVE"),
            WorkspaceStatus::Creating => write!(f, "CREATING"),
            WorkspaceStatus::CreationFailed => write!(f, "CREATION_FAILED"),
            WorkspaceStatus::Deleting => write!(f, "DELETING"),
            WorkspaceStatus::DeletionFailed => write!(f, "DELETION_FAILED"),
            WorkspaceStatus::Failed => write!(f, "FAILED"),
            WorkspaceStatus::LicenseRemovalFailed => write!(f, "LICENSE_REMOVAL_FAILED"),
            WorkspaceStatus::UpdateFailed => write!(f, "UPDATE_FAILED"),
            WorkspaceStatus::Updating => write!(f, "UPDATING"),
            WorkspaceStatus::UpgradeFailed => write!(f, "UPGRADE_FAILED"),
            WorkspaceStatus::Upgrading => write!(f, "UPGRADING"),
            WorkspaceStatus::VersionUpdateFailed => write!(f, "VERSION_UPDATE_FAILED"),
            WorkspaceStatus::VersionUpdating => write!(f, "VERSION_UPDATING"),
            WorkspaceStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
