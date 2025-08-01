// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ContactInitiationMethod`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let contactinitiationmethod = unimplemented!();
/// match contactinitiationmethod {
///     ContactInitiationMethod::AgentReply => { /* ... */ },
///     ContactInitiationMethod::Api => { /* ... */ },
///     ContactInitiationMethod::Callback => { /* ... */ },
///     ContactInitiationMethod::Disconnect => { /* ... */ },
///     ContactInitiationMethod::ExternalOutbound => { /* ... */ },
///     ContactInitiationMethod::Flow => { /* ... */ },
///     ContactInitiationMethod::Inbound => { /* ... */ },
///     ContactInitiationMethod::Monitor => { /* ... */ },
///     ContactInitiationMethod::Outbound => { /* ... */ },
///     ContactInitiationMethod::QueueTransfer => { /* ... */ },
///     ContactInitiationMethod::Transfer => { /* ... */ },
///     ContactInitiationMethod::WebrtcApi => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `contactinitiationmethod` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ContactInitiationMethod::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ContactInitiationMethod::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ContactInitiationMethod::NewFeature` is defined.
/// Specifically, when `contactinitiationmethod` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ContactInitiationMethod::NewFeature` also yielding `"NewFeature"`.
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
pub enum ContactInitiationMethod {
    #[allow(missing_docs)] // documentation missing in model
    AgentReply,
    #[allow(missing_docs)] // documentation missing in model
    Api,
    #[allow(missing_docs)] // documentation missing in model
    Callback,
    #[allow(missing_docs)] // documentation missing in model
    Disconnect,
    #[allow(missing_docs)] // documentation missing in model
    ExternalOutbound,
    #[allow(missing_docs)] // documentation missing in model
    Flow,
    #[allow(missing_docs)] // documentation missing in model
    Inbound,
    #[allow(missing_docs)] // documentation missing in model
    Monitor,
    #[allow(missing_docs)] // documentation missing in model
    Outbound,
    #[allow(missing_docs)] // documentation missing in model
    QueueTransfer,
    #[allow(missing_docs)] // documentation missing in model
    Transfer,
    #[allow(missing_docs)] // documentation missing in model
    WebrtcApi,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ContactInitiationMethod {
    fn from(s: &str) -> Self {
        match s {
            "AGENT_REPLY" => ContactInitiationMethod::AgentReply,
            "API" => ContactInitiationMethod::Api,
            "CALLBACK" => ContactInitiationMethod::Callback,
            "DISCONNECT" => ContactInitiationMethod::Disconnect,
            "EXTERNAL_OUTBOUND" => ContactInitiationMethod::ExternalOutbound,
            "FLOW" => ContactInitiationMethod::Flow,
            "INBOUND" => ContactInitiationMethod::Inbound,
            "MONITOR" => ContactInitiationMethod::Monitor,
            "OUTBOUND" => ContactInitiationMethod::Outbound,
            "QUEUE_TRANSFER" => ContactInitiationMethod::QueueTransfer,
            "TRANSFER" => ContactInitiationMethod::Transfer,
            "WEBRTC_API" => ContactInitiationMethod::WebrtcApi,
            other => ContactInitiationMethod::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ContactInitiationMethod {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ContactInitiationMethod::from(s))
    }
}
impl ContactInitiationMethod {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ContactInitiationMethod::AgentReply => "AGENT_REPLY",
            ContactInitiationMethod::Api => "API",
            ContactInitiationMethod::Callback => "CALLBACK",
            ContactInitiationMethod::Disconnect => "DISCONNECT",
            ContactInitiationMethod::ExternalOutbound => "EXTERNAL_OUTBOUND",
            ContactInitiationMethod::Flow => "FLOW",
            ContactInitiationMethod::Inbound => "INBOUND",
            ContactInitiationMethod::Monitor => "MONITOR",
            ContactInitiationMethod::Outbound => "OUTBOUND",
            ContactInitiationMethod::QueueTransfer => "QUEUE_TRANSFER",
            ContactInitiationMethod::Transfer => "TRANSFER",
            ContactInitiationMethod::WebrtcApi => "WEBRTC_API",
            ContactInitiationMethod::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AGENT_REPLY",
            "API",
            "CALLBACK",
            "DISCONNECT",
            "EXTERNAL_OUTBOUND",
            "FLOW",
            "INBOUND",
            "MONITOR",
            "OUTBOUND",
            "QUEUE_TRANSFER",
            "TRANSFER",
            "WEBRTC_API",
        ]
    }
}
impl ::std::convert::AsRef<str> for ContactInitiationMethod {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ContactInitiationMethod {
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
impl ::std::fmt::Display for ContactInitiationMethod {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ContactInitiationMethod::AgentReply => write!(f, "AGENT_REPLY"),
            ContactInitiationMethod::Api => write!(f, "API"),
            ContactInitiationMethod::Callback => write!(f, "CALLBACK"),
            ContactInitiationMethod::Disconnect => write!(f, "DISCONNECT"),
            ContactInitiationMethod::ExternalOutbound => write!(f, "EXTERNAL_OUTBOUND"),
            ContactInitiationMethod::Flow => write!(f, "FLOW"),
            ContactInitiationMethod::Inbound => write!(f, "INBOUND"),
            ContactInitiationMethod::Monitor => write!(f, "MONITOR"),
            ContactInitiationMethod::Outbound => write!(f, "OUTBOUND"),
            ContactInitiationMethod::QueueTransfer => write!(f, "QUEUE_TRANSFER"),
            ContactInitiationMethod::Transfer => write!(f, "TRANSFER"),
            ContactInitiationMethod::WebrtcApi => write!(f, "WEBRTC_API"),
            ContactInitiationMethod::Unknown(value) => write!(f, "{}", value),
        }
    }
}
