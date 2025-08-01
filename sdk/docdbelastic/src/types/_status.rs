// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `Status`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let status = unimplemented!();
/// match status {
///     Status::Active => { /* ... */ },
///     Status::Copying => { /* ... */ },
///     Status::Creating => { /* ... */ },
///     Status::Deleting => { /* ... */ },
///     Status::InaccessibleEncryptionCredentialsRecoverable => { /* ... */ },
///     Status::InaccessibleEncryptionCreds => { /* ... */ },
///     Status::InaccessibleSecretArn => { /* ... */ },
///     Status::InaccessibleVpcEndpoint => { /* ... */ },
///     Status::IncompatibleNetwork => { /* ... */ },
///     Status::InvalidSecurityGroupId => { /* ... */ },
///     Status::InvalidSubnetId => { /* ... */ },
///     Status::IpAddressLimitExceeded => { /* ... */ },
///     Status::Maintenance => { /* ... */ },
///     Status::Merging => { /* ... */ },
///     Status::Modifying => { /* ... */ },
///     Status::Splitting => { /* ... */ },
///     Status::Starting => { /* ... */ },
///     Status::Stopped => { /* ... */ },
///     Status::Stopping => { /* ... */ },
///     Status::Updating => { /* ... */ },
///     Status::VpcEndpointLimitExceeded => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `status` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `Status::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `Status::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `Status::NewFeature` is defined.
/// Specifically, when `status` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `Status::NewFeature` also yielding `"NewFeature"`.
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
pub enum Status {
    #[allow(missing_docs)] // documentation missing in model
    Active,
    #[allow(missing_docs)] // documentation missing in model
    Copying,
    #[allow(missing_docs)] // documentation missing in model
    Creating,
    #[allow(missing_docs)] // documentation missing in model
    Deleting,
    #[allow(missing_docs)] // documentation missing in model
    InaccessibleEncryptionCredentialsRecoverable,
    #[allow(missing_docs)] // documentation missing in model
    InaccessibleEncryptionCreds,
    #[allow(missing_docs)] // documentation missing in model
    InaccessibleSecretArn,
    #[allow(missing_docs)] // documentation missing in model
    InaccessibleVpcEndpoint,
    #[allow(missing_docs)] // documentation missing in model
    IncompatibleNetwork,
    #[allow(missing_docs)] // documentation missing in model
    InvalidSecurityGroupId,
    #[allow(missing_docs)] // documentation missing in model
    InvalidSubnetId,
    #[allow(missing_docs)] // documentation missing in model
    IpAddressLimitExceeded,
    #[allow(missing_docs)] // documentation missing in model
    Maintenance,
    #[allow(missing_docs)] // documentation missing in model
    Merging,
    #[allow(missing_docs)] // documentation missing in model
    Modifying,
    #[allow(missing_docs)] // documentation missing in model
    Splitting,
    #[allow(missing_docs)] // documentation missing in model
    Starting,
    #[allow(missing_docs)] // documentation missing in model
    Stopped,
    #[allow(missing_docs)] // documentation missing in model
    Stopping,
    #[allow(missing_docs)] // documentation missing in model
    Updating,
    #[allow(missing_docs)] // documentation missing in model
    VpcEndpointLimitExceeded,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for Status {
    fn from(s: &str) -> Self {
        match s {
            "ACTIVE" => Status::Active,
            "COPYING" => Status::Copying,
            "CREATING" => Status::Creating,
            "DELETING" => Status::Deleting,
            "INACCESSIBLE_ENCRYPTION_CREDENTIALS_RECOVERABLE" => Status::InaccessibleEncryptionCredentialsRecoverable,
            "INACCESSIBLE_ENCRYPTION_CREDS" => Status::InaccessibleEncryptionCreds,
            "INACCESSIBLE_SECRET_ARN" => Status::InaccessibleSecretArn,
            "INACCESSIBLE_VPC_ENDPOINT" => Status::InaccessibleVpcEndpoint,
            "INCOMPATIBLE_NETWORK" => Status::IncompatibleNetwork,
            "INVALID_SECURITY_GROUP_ID" => Status::InvalidSecurityGroupId,
            "INVALID_SUBNET_ID" => Status::InvalidSubnetId,
            "IP_ADDRESS_LIMIT_EXCEEDED" => Status::IpAddressLimitExceeded,
            "MAINTENANCE" => Status::Maintenance,
            "MERGING" => Status::Merging,
            "MODIFYING" => Status::Modifying,
            "SPLITTING" => Status::Splitting,
            "STARTING" => Status::Starting,
            "STOPPED" => Status::Stopped,
            "STOPPING" => Status::Stopping,
            "UPDATING" => Status::Updating,
            "VPC_ENDPOINT_LIMIT_EXCEEDED" => Status::VpcEndpointLimitExceeded,
            other => Status::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for Status {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(Status::from(s))
    }
}
impl Status {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            Status::Active => "ACTIVE",
            Status::Copying => "COPYING",
            Status::Creating => "CREATING",
            Status::Deleting => "DELETING",
            Status::InaccessibleEncryptionCredentialsRecoverable => "INACCESSIBLE_ENCRYPTION_CREDENTIALS_RECOVERABLE",
            Status::InaccessibleEncryptionCreds => "INACCESSIBLE_ENCRYPTION_CREDS",
            Status::InaccessibleSecretArn => "INACCESSIBLE_SECRET_ARN",
            Status::InaccessibleVpcEndpoint => "INACCESSIBLE_VPC_ENDPOINT",
            Status::IncompatibleNetwork => "INCOMPATIBLE_NETWORK",
            Status::InvalidSecurityGroupId => "INVALID_SECURITY_GROUP_ID",
            Status::InvalidSubnetId => "INVALID_SUBNET_ID",
            Status::IpAddressLimitExceeded => "IP_ADDRESS_LIMIT_EXCEEDED",
            Status::Maintenance => "MAINTENANCE",
            Status::Merging => "MERGING",
            Status::Modifying => "MODIFYING",
            Status::Splitting => "SPLITTING",
            Status::Starting => "STARTING",
            Status::Stopped => "STOPPED",
            Status::Stopping => "STOPPING",
            Status::Updating => "UPDATING",
            Status::VpcEndpointLimitExceeded => "VPC_ENDPOINT_LIMIT_EXCEEDED",
            Status::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACTIVE",
            "COPYING",
            "CREATING",
            "DELETING",
            "INACCESSIBLE_ENCRYPTION_CREDENTIALS_RECOVERABLE",
            "INACCESSIBLE_ENCRYPTION_CREDS",
            "INACCESSIBLE_SECRET_ARN",
            "INACCESSIBLE_VPC_ENDPOINT",
            "INCOMPATIBLE_NETWORK",
            "INVALID_SECURITY_GROUP_ID",
            "INVALID_SUBNET_ID",
            "IP_ADDRESS_LIMIT_EXCEEDED",
            "MAINTENANCE",
            "MERGING",
            "MODIFYING",
            "SPLITTING",
            "STARTING",
            "STOPPED",
            "STOPPING",
            "UPDATING",
            "VPC_ENDPOINT_LIMIT_EXCEEDED",
        ]
    }
}
impl ::std::convert::AsRef<str> for Status {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Status {
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
impl ::std::fmt::Display for Status {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Status::Active => write!(f, "ACTIVE"),
            Status::Copying => write!(f, "COPYING"),
            Status::Creating => write!(f, "CREATING"),
            Status::Deleting => write!(f, "DELETING"),
            Status::InaccessibleEncryptionCredentialsRecoverable => write!(f, "INACCESSIBLE_ENCRYPTION_CREDENTIALS_RECOVERABLE"),
            Status::InaccessibleEncryptionCreds => write!(f, "INACCESSIBLE_ENCRYPTION_CREDS"),
            Status::InaccessibleSecretArn => write!(f, "INACCESSIBLE_SECRET_ARN"),
            Status::InaccessibleVpcEndpoint => write!(f, "INACCESSIBLE_VPC_ENDPOINT"),
            Status::IncompatibleNetwork => write!(f, "INCOMPATIBLE_NETWORK"),
            Status::InvalidSecurityGroupId => write!(f, "INVALID_SECURITY_GROUP_ID"),
            Status::InvalidSubnetId => write!(f, "INVALID_SUBNET_ID"),
            Status::IpAddressLimitExceeded => write!(f, "IP_ADDRESS_LIMIT_EXCEEDED"),
            Status::Maintenance => write!(f, "MAINTENANCE"),
            Status::Merging => write!(f, "MERGING"),
            Status::Modifying => write!(f, "MODIFYING"),
            Status::Splitting => write!(f, "SPLITTING"),
            Status::Starting => write!(f, "STARTING"),
            Status::Stopped => write!(f, "STOPPED"),
            Status::Stopping => write!(f, "STOPPING"),
            Status::Updating => write!(f, "UPDATING"),
            Status::VpcEndpointLimitExceeded => write!(f, "VPC_ENDPOINT_LIMIT_EXCEEDED"),
            Status::Unknown(value) => write!(f, "{}", value),
        }
    }
}
