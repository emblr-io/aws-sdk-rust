// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details for how an approval team grants approval.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum ApprovalStrategyResponse {
    /// <p>Minimum number of approvals (M) required for a total number of approvers (N).</p>
    MofN(crate::types::MofNApprovalStrategy),
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
impl ApprovalStrategyResponse {
    #[allow(irrefutable_let_patterns)]
    /// Tries to convert the enum instance into [`MofN`](crate::types::ApprovalStrategyResponse::MofN), extracting the inner [`MofNApprovalStrategy`](crate::types::MofNApprovalStrategy).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_mof_n(&self) -> ::std::result::Result<&crate::types::MofNApprovalStrategy, &Self> {
        if let ApprovalStrategyResponse::MofN(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`MofN`](crate::types::ApprovalStrategyResponse::MofN).
    pub fn is_mof_n(&self) -> bool {
        self.as_mof_n().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
