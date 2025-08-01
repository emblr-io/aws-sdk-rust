// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of service integrations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum ServiceIntegrationsUnion {
    /// <p>A list of scopes set up for Lake Formation integration.</p>
    LakeFormation(::std::vec::Vec<crate::types::LakeFormationScopeUnion>),
    /// <p>A list of scopes set up for S3 Access Grants integration.</p>
    S3AccessGrants(::std::vec::Vec<crate::types::S3AccessGrantsScopeUnion>),
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
impl ServiceIntegrationsUnion {
    /// Tries to convert the enum instance into [`LakeFormation`](crate::types::ServiceIntegrationsUnion::LakeFormation), extracting the inner [`Vec`](::std::vec::Vec).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_lake_formation(&self) -> ::std::result::Result<&::std::vec::Vec<crate::types::LakeFormationScopeUnion>, &Self> {
        if let ServiceIntegrationsUnion::LakeFormation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`LakeFormation`](crate::types::ServiceIntegrationsUnion::LakeFormation).
    pub fn is_lake_formation(&self) -> bool {
        self.as_lake_formation().is_ok()
    }
    /// Tries to convert the enum instance into [`S3AccessGrants`](crate::types::ServiceIntegrationsUnion::S3AccessGrants), extracting the inner [`Vec`](::std::vec::Vec).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_s3_access_grants(&self) -> ::std::result::Result<&::std::vec::Vec<crate::types::S3AccessGrantsScopeUnion>, &Self> {
        if let ServiceIntegrationsUnion::S3AccessGrants(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`S3AccessGrants`](crate::types::ServiceIntegrationsUnion::S3AccessGrants).
    pub fn is_s3_access_grants(&self) -> bool {
        self.as_s3_access_grants().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
