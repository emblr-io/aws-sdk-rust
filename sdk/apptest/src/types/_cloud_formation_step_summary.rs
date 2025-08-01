// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the CloudFormation step summary.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum CloudFormationStepSummary {
    /// <p>Creates the CloudFormation summary of the step.</p>
    CreateCloudformation(crate::types::CreateCloudFormationSummary),
    /// <p>Deletes the CloudFormation summary of the CloudFormation step summary.</p>
    DeleteCloudformation(crate::types::DeleteCloudFormationSummary),
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
impl CloudFormationStepSummary {
    /// Tries to convert the enum instance into [`CreateCloudformation`](crate::types::CloudFormationStepSummary::CreateCloudformation), extracting the inner [`CreateCloudFormationSummary`](crate::types::CreateCloudFormationSummary).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_create_cloudformation(&self) -> ::std::result::Result<&crate::types::CreateCloudFormationSummary, &Self> {
        if let CloudFormationStepSummary::CreateCloudformation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CreateCloudformation`](crate::types::CloudFormationStepSummary::CreateCloudformation).
    pub fn is_create_cloudformation(&self) -> bool {
        self.as_create_cloudformation().is_ok()
    }
    /// Tries to convert the enum instance into [`DeleteCloudformation`](crate::types::CloudFormationStepSummary::DeleteCloudformation), extracting the inner [`DeleteCloudFormationSummary`](crate::types::DeleteCloudFormationSummary).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_delete_cloudformation(&self) -> ::std::result::Result<&crate::types::DeleteCloudFormationSummary, &Self> {
        if let CloudFormationStepSummary::DeleteCloudformation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DeleteCloudformation`](crate::types::CloudFormationStepSummary::DeleteCloudformation).
    pub fn is_delete_cloudformation(&self) -> bool {
        self.as_delete_cloudformation().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
