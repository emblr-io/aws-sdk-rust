// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Object to store union of values for a provisioned cluster or serverless namespace’s identifier.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum NamespaceIdentifierUnion {
    /// <p>The identifier for a provisioned cluster.</p>
    ProvisionedIdentifier(crate::types::ProvisionedIdentifier),
    /// <p>The identifier for a serverless namespace.</p>
    ServerlessIdentifier(crate::types::ServerlessIdentifier),
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
impl NamespaceIdentifierUnion {
    /// Tries to convert the enum instance into [`ProvisionedIdentifier`](crate::types::NamespaceIdentifierUnion::ProvisionedIdentifier), extracting the inner [`ProvisionedIdentifier`](crate::types::ProvisionedIdentifier).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_provisioned_identifier(&self) -> ::std::result::Result<&crate::types::ProvisionedIdentifier, &Self> {
        if let NamespaceIdentifierUnion::ProvisionedIdentifier(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ProvisionedIdentifier`](crate::types::NamespaceIdentifierUnion::ProvisionedIdentifier).
    pub fn is_provisioned_identifier(&self) -> bool {
        self.as_provisioned_identifier().is_ok()
    }
    /// Tries to convert the enum instance into [`ServerlessIdentifier`](crate::types::NamespaceIdentifierUnion::ServerlessIdentifier), extracting the inner [`ServerlessIdentifier`](crate::types::ServerlessIdentifier).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_serverless_identifier(&self) -> ::std::result::Result<&crate::types::ServerlessIdentifier, &Self> {
        if let NamespaceIdentifierUnion::ServerlessIdentifier(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ServerlessIdentifier`](crate::types::NamespaceIdentifierUnion::ServerlessIdentifier).
    pub fn is_serverless_identifier(&self) -> bool {
        self.as_serverless_identifier().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
