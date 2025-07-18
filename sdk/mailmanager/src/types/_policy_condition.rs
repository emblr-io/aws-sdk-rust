// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The email traffic filtering conditions which are contained in a traffic policy resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum PolicyCondition {
    /// <p>This represents a boolean type condition matching on the incoming mail. It performs the boolean operation configured in 'Operator' and evaluates the 'Protocol' object against the 'Value'.</p>
    BooleanExpression(crate::types::IngressBooleanExpression),
    /// <p>This represents an IP based condition matching on the incoming mail. It performs the operation configured in 'Operator' and evaluates the 'Protocol' object against the 'Value'.</p>
    IpExpression(crate::types::IngressIpv4Expression),
    /// <p>This represents an IPv6 based condition matching on the incoming mail. It performs the operation configured in 'Operator' and evaluates the 'Protocol' object against the 'Value'.</p>
    Ipv6Expression(crate::types::IngressIpv6Expression),
    /// <p>This represents a string based condition matching on the incoming mail. It performs the string operation configured in 'Operator' and evaluates the 'Protocol' object against the 'Value'.</p>
    StringExpression(crate::types::IngressStringExpression),
    /// <p>This represents a TLS based condition matching on the incoming mail. It performs the operation configured in 'Operator' and evaluates the 'Protocol' object against the 'Value'.</p>
    TlsExpression(crate::types::IngressTlsProtocolExpression),
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
impl PolicyCondition {
    /// Tries to convert the enum instance into [`BooleanExpression`](crate::types::PolicyCondition::BooleanExpression), extracting the inner [`IngressBooleanExpression`](crate::types::IngressBooleanExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_boolean_expression(&self) -> ::std::result::Result<&crate::types::IngressBooleanExpression, &Self> {
        if let PolicyCondition::BooleanExpression(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`BooleanExpression`](crate::types::PolicyCondition::BooleanExpression).
    pub fn is_boolean_expression(&self) -> bool {
        self.as_boolean_expression().is_ok()
    }
    /// Tries to convert the enum instance into [`IpExpression`](crate::types::PolicyCondition::IpExpression), extracting the inner [`IngressIpv4Expression`](crate::types::IngressIpv4Expression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_ip_expression(&self) -> ::std::result::Result<&crate::types::IngressIpv4Expression, &Self> {
        if let PolicyCondition::IpExpression(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`IpExpression`](crate::types::PolicyCondition::IpExpression).
    pub fn is_ip_expression(&self) -> bool {
        self.as_ip_expression().is_ok()
    }
    /// Tries to convert the enum instance into [`Ipv6Expression`](crate::types::PolicyCondition::Ipv6Expression), extracting the inner [`IngressIpv6Expression`](crate::types::IngressIpv6Expression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_ipv6_expression(&self) -> ::std::result::Result<&crate::types::IngressIpv6Expression, &Self> {
        if let PolicyCondition::Ipv6Expression(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Ipv6Expression`](crate::types::PolicyCondition::Ipv6Expression).
    pub fn is_ipv6_expression(&self) -> bool {
        self.as_ipv6_expression().is_ok()
    }
    /// Tries to convert the enum instance into [`StringExpression`](crate::types::PolicyCondition::StringExpression), extracting the inner [`IngressStringExpression`](crate::types::IngressStringExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_string_expression(&self) -> ::std::result::Result<&crate::types::IngressStringExpression, &Self> {
        if let PolicyCondition::StringExpression(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`StringExpression`](crate::types::PolicyCondition::StringExpression).
    pub fn is_string_expression(&self) -> bool {
        self.as_string_expression().is_ok()
    }
    /// Tries to convert the enum instance into [`TlsExpression`](crate::types::PolicyCondition::TlsExpression), extracting the inner [`IngressTlsProtocolExpression`](crate::types::IngressTlsProtocolExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_tls_expression(&self) -> ::std::result::Result<&crate::types::IngressTlsProtocolExpression, &Self> {
        if let PolicyCondition::TlsExpression(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`TlsExpression`](crate::types::PolicyCondition::TlsExpression).
    pub fn is_tls_expression(&self) -> bool {
        self.as_tls_expression().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
