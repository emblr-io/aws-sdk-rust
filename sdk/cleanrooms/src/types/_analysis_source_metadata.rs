// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The analysis source metadata.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum AnalysisSourceMetadata {
    /// <p>The artifacts of the analysis source metadata.</p>
    Artifacts(crate::types::AnalysisTemplateArtifactMetadata),
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
impl AnalysisSourceMetadata {
    #[allow(irrefutable_let_patterns)]
    /// Tries to convert the enum instance into [`Artifacts`](crate::types::AnalysisSourceMetadata::Artifacts), extracting the inner [`AnalysisTemplateArtifactMetadata`](crate::types::AnalysisTemplateArtifactMetadata).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_artifacts(&self) -> ::std::result::Result<&crate::types::AnalysisTemplateArtifactMetadata, &Self> {
        if let AnalysisSourceMetadata::Artifacts(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Artifacts`](crate::types::AnalysisSourceMetadata::Artifacts).
    pub fn is_artifacts(&self) -> bool {
        self.as_artifacts().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
