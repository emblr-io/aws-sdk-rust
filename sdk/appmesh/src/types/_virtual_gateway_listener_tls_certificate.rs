// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a listener's Transport Layer Security (TLS) certificate.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum VirtualGatewayListenerTlsCertificate {
    /// <p>A reference to an object that represents an Certificate Manager certificate.</p>
    Acm(crate::types::VirtualGatewayListenerTlsAcmCertificate),
    /// <p>A reference to an object that represents a local file certificate.</p>
    File(crate::types::VirtualGatewayListenerTlsFileCertificate),
    /// <p>A reference to an object that represents a virtual gateway's listener's Secret Discovery Service certificate.</p>
    Sds(crate::types::VirtualGatewayListenerTlsSdsCertificate),
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
impl VirtualGatewayListenerTlsCertificate {
    /// Tries to convert the enum instance into [`Acm`](crate::types::VirtualGatewayListenerTlsCertificate::Acm), extracting the inner [`VirtualGatewayListenerTlsAcmCertificate`](crate::types::VirtualGatewayListenerTlsAcmCertificate).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_acm(&self) -> ::std::result::Result<&crate::types::VirtualGatewayListenerTlsAcmCertificate, &Self> {
        if let VirtualGatewayListenerTlsCertificate::Acm(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Acm`](crate::types::VirtualGatewayListenerTlsCertificate::Acm).
    pub fn is_acm(&self) -> bool {
        self.as_acm().is_ok()
    }
    /// Tries to convert the enum instance into [`File`](crate::types::VirtualGatewayListenerTlsCertificate::File), extracting the inner [`VirtualGatewayListenerTlsFileCertificate`](crate::types::VirtualGatewayListenerTlsFileCertificate).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_file(&self) -> ::std::result::Result<&crate::types::VirtualGatewayListenerTlsFileCertificate, &Self> {
        if let VirtualGatewayListenerTlsCertificate::File(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`File`](crate::types::VirtualGatewayListenerTlsCertificate::File).
    pub fn is_file(&self) -> bool {
        self.as_file().is_ok()
    }
    /// Tries to convert the enum instance into [`Sds`](crate::types::VirtualGatewayListenerTlsCertificate::Sds), extracting the inner [`VirtualGatewayListenerTlsSdsCertificate`](crate::types::VirtualGatewayListenerTlsSdsCertificate).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_sds(&self) -> ::std::result::Result<&crate::types::VirtualGatewayListenerTlsSdsCertificate, &Self> {
        if let VirtualGatewayListenerTlsCertificate::Sds(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Sds`](crate::types::VirtualGatewayListenerTlsCertificate::Sds).
    pub fn is_sds(&self) -> bool {
        self.as_sds().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
