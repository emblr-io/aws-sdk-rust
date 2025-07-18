// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AttachmentErrorCode`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let attachmenterrorcode = unimplemented!();
/// match attachmenterrorcode {
///     AttachmentErrorCode::DirectConnectGatewayExistingAttachments => { /* ... */ },
///     AttachmentErrorCode::DirectConnectGatewayNotFound => { /* ... */ },
///     AttachmentErrorCode::DirectConnectGatewayNoPrivateVif => { /* ... */ },
///     AttachmentErrorCode::MaximumNoEncapLimitExceeded => { /* ... */ },
///     AttachmentErrorCode::SubnetDuplicatedInAvailabilityZone => { /* ... */ },
///     AttachmentErrorCode::SubnetNotFound => { /* ... */ },
///     AttachmentErrorCode::SubnetNoFreeAddresses => { /* ... */ },
///     AttachmentErrorCode::SubnetNoIpv6Cidrs => { /* ... */ },
///     AttachmentErrorCode::SubnetUnsupportedAvailabilityZone => { /* ... */ },
///     AttachmentErrorCode::VpcNotFound => { /* ... */ },
///     AttachmentErrorCode::VpnConnectionNotFound => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `attachmenterrorcode` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AttachmentErrorCode::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AttachmentErrorCode::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AttachmentErrorCode::NewFeature` is defined.
/// Specifically, when `attachmenterrorcode` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AttachmentErrorCode::NewFeature` also yielding `"NewFeature"`.
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
pub enum AttachmentErrorCode {
    #[allow(missing_docs)] // documentation missing in model
    DirectConnectGatewayExistingAttachments,
    #[allow(missing_docs)] // documentation missing in model
    DirectConnectGatewayNotFound,
    #[allow(missing_docs)] // documentation missing in model
    DirectConnectGatewayNoPrivateVif,
    #[allow(missing_docs)] // documentation missing in model
    MaximumNoEncapLimitExceeded,
    #[allow(missing_docs)] // documentation missing in model
    SubnetDuplicatedInAvailabilityZone,
    #[allow(missing_docs)] // documentation missing in model
    SubnetNotFound,
    #[allow(missing_docs)] // documentation missing in model
    SubnetNoFreeAddresses,
    #[allow(missing_docs)] // documentation missing in model
    SubnetNoIpv6Cidrs,
    #[allow(missing_docs)] // documentation missing in model
    SubnetUnsupportedAvailabilityZone,
    #[allow(missing_docs)] // documentation missing in model
    VpcNotFound,
    #[allow(missing_docs)] // documentation missing in model
    VpnConnectionNotFound,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AttachmentErrorCode {
    fn from(s: &str) -> Self {
        match s {
            "DIRECT_CONNECT_GATEWAY_EXISTING_ATTACHMENTS" => AttachmentErrorCode::DirectConnectGatewayExistingAttachments,
            "DIRECT_CONNECT_GATEWAY_NOT_FOUND" => AttachmentErrorCode::DirectConnectGatewayNotFound,
            "DIRECT_CONNECT_GATEWAY_NO_PRIVATE_VIF" => AttachmentErrorCode::DirectConnectGatewayNoPrivateVif,
            "MAXIMUM_NO_ENCAP_LIMIT_EXCEEDED" => AttachmentErrorCode::MaximumNoEncapLimitExceeded,
            "SUBNET_DUPLICATED_IN_AVAILABILITY_ZONE" => AttachmentErrorCode::SubnetDuplicatedInAvailabilityZone,
            "SUBNET_NOT_FOUND" => AttachmentErrorCode::SubnetNotFound,
            "SUBNET_NO_FREE_ADDRESSES" => AttachmentErrorCode::SubnetNoFreeAddresses,
            "SUBNET_NO_IPV6_CIDRS" => AttachmentErrorCode::SubnetNoIpv6Cidrs,
            "SUBNET_UNSUPPORTED_AVAILABILITY_ZONE" => AttachmentErrorCode::SubnetUnsupportedAvailabilityZone,
            "VPC_NOT_FOUND" => AttachmentErrorCode::VpcNotFound,
            "VPN_CONNECTION_NOT_FOUND" => AttachmentErrorCode::VpnConnectionNotFound,
            other => AttachmentErrorCode::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AttachmentErrorCode {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AttachmentErrorCode::from(s))
    }
}
impl AttachmentErrorCode {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AttachmentErrorCode::DirectConnectGatewayExistingAttachments => "DIRECT_CONNECT_GATEWAY_EXISTING_ATTACHMENTS",
            AttachmentErrorCode::DirectConnectGatewayNotFound => "DIRECT_CONNECT_GATEWAY_NOT_FOUND",
            AttachmentErrorCode::DirectConnectGatewayNoPrivateVif => "DIRECT_CONNECT_GATEWAY_NO_PRIVATE_VIF",
            AttachmentErrorCode::MaximumNoEncapLimitExceeded => "MAXIMUM_NO_ENCAP_LIMIT_EXCEEDED",
            AttachmentErrorCode::SubnetDuplicatedInAvailabilityZone => "SUBNET_DUPLICATED_IN_AVAILABILITY_ZONE",
            AttachmentErrorCode::SubnetNotFound => "SUBNET_NOT_FOUND",
            AttachmentErrorCode::SubnetNoFreeAddresses => "SUBNET_NO_FREE_ADDRESSES",
            AttachmentErrorCode::SubnetNoIpv6Cidrs => "SUBNET_NO_IPV6_CIDRS",
            AttachmentErrorCode::SubnetUnsupportedAvailabilityZone => "SUBNET_UNSUPPORTED_AVAILABILITY_ZONE",
            AttachmentErrorCode::VpcNotFound => "VPC_NOT_FOUND",
            AttachmentErrorCode::VpnConnectionNotFound => "VPN_CONNECTION_NOT_FOUND",
            AttachmentErrorCode::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "DIRECT_CONNECT_GATEWAY_EXISTING_ATTACHMENTS",
            "DIRECT_CONNECT_GATEWAY_NOT_FOUND",
            "DIRECT_CONNECT_GATEWAY_NO_PRIVATE_VIF",
            "MAXIMUM_NO_ENCAP_LIMIT_EXCEEDED",
            "SUBNET_DUPLICATED_IN_AVAILABILITY_ZONE",
            "SUBNET_NOT_FOUND",
            "SUBNET_NO_FREE_ADDRESSES",
            "SUBNET_NO_IPV6_CIDRS",
            "SUBNET_UNSUPPORTED_AVAILABILITY_ZONE",
            "VPC_NOT_FOUND",
            "VPN_CONNECTION_NOT_FOUND",
        ]
    }
}
impl ::std::convert::AsRef<str> for AttachmentErrorCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AttachmentErrorCode {
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
impl ::std::fmt::Display for AttachmentErrorCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AttachmentErrorCode::DirectConnectGatewayExistingAttachments => write!(f, "DIRECT_CONNECT_GATEWAY_EXISTING_ATTACHMENTS"),
            AttachmentErrorCode::DirectConnectGatewayNotFound => write!(f, "DIRECT_CONNECT_GATEWAY_NOT_FOUND"),
            AttachmentErrorCode::DirectConnectGatewayNoPrivateVif => write!(f, "DIRECT_CONNECT_GATEWAY_NO_PRIVATE_VIF"),
            AttachmentErrorCode::MaximumNoEncapLimitExceeded => write!(f, "MAXIMUM_NO_ENCAP_LIMIT_EXCEEDED"),
            AttachmentErrorCode::SubnetDuplicatedInAvailabilityZone => write!(f, "SUBNET_DUPLICATED_IN_AVAILABILITY_ZONE"),
            AttachmentErrorCode::SubnetNotFound => write!(f, "SUBNET_NOT_FOUND"),
            AttachmentErrorCode::SubnetNoFreeAddresses => write!(f, "SUBNET_NO_FREE_ADDRESSES"),
            AttachmentErrorCode::SubnetNoIpv6Cidrs => write!(f, "SUBNET_NO_IPV6_CIDRS"),
            AttachmentErrorCode::SubnetUnsupportedAvailabilityZone => write!(f, "SUBNET_UNSUPPORTED_AVAILABILITY_ZONE"),
            AttachmentErrorCode::VpcNotFound => write!(f, "VPC_NOT_FOUND"),
            AttachmentErrorCode::VpnConnectionNotFound => write!(f, "VPN_CONNECTION_NOT_FOUND"),
            AttachmentErrorCode::Unknown(value) => write!(f, "{}", value),
        }
    }
}
