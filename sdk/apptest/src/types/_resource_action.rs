// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a resource action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum ResourceAction {
    /// <p>The CloudFormation action of the resource action.</p>
    CloudFormationAction(crate::types::CloudFormationAction),
    /// <p>The AWS Mainframe Modernization managed application action of the resource action.</p>
    M2ManagedApplicationAction(crate::types::M2ManagedApplicationAction),
    /// <p>The AWS Mainframe Modernization non-managed application action of the resource action.</p>
    M2NonManagedApplicationAction(crate::types::M2NonManagedApplicationAction),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl ResourceAction {
    /// Tries to convert the enum instance into [`CloudFormationAction`](crate::types::ResourceAction::CloudFormationAction), extracting the inner [`CloudFormationAction`](crate::types::CloudFormationAction).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_cloud_formation_action(&self) -> ::std::result::Result<&crate::types::CloudFormationAction, &Self> {
        if let ResourceAction::CloudFormationAction(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CloudFormationAction`](crate::types::ResourceAction::CloudFormationAction).
    pub fn is_cloud_formation_action(&self) -> bool {
        self.as_cloud_formation_action().is_ok()
    }
    /// Tries to convert the enum instance into [`M2ManagedApplicationAction`](crate::types::ResourceAction::M2ManagedApplicationAction), extracting the inner [`M2ManagedApplicationAction`](crate::types::M2ManagedApplicationAction).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_m2_managed_application_action(&self) -> ::std::result::Result<&crate::types::M2ManagedApplicationAction, &Self> {
        if let ResourceAction::M2ManagedApplicationAction(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`M2ManagedApplicationAction`](crate::types::ResourceAction::M2ManagedApplicationAction).
    pub fn is_m2_managed_application_action(&self) -> bool {
        self.as_m2_managed_application_action().is_ok()
    }
    /// Tries to convert the enum instance into [`M2NonManagedApplicationAction`](crate::types::ResourceAction::M2NonManagedApplicationAction), extracting the inner [`M2NonManagedApplicationAction`](crate::types::M2NonManagedApplicationAction).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_m2_non_managed_application_action(&self) -> ::std::result::Result<&crate::types::M2NonManagedApplicationAction, &Self> {
        if let ResourceAction::M2NonManagedApplicationAction(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`M2NonManagedApplicationAction`](crate::types::ResourceAction::M2NonManagedApplicationAction).
    pub fn is_m2_non_managed_application_action(&self) -> bool {
        self.as_m2_non_managed_application_action().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
