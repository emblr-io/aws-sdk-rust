// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `EventType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let eventtype = unimplemented!();
/// match eventtype {
///     EventType::AccountAssociation => { /* ... */ },
///     EventType::ConnectorAssociation => { /* ... */ },
///     EventType::ConnectorErrorReport => { /* ... */ },
///     EventType::DeviceCommand => { /* ... */ },
///     EventType::DeviceCommandRequest => { /* ... */ },
///     EventType::DeviceDiscoveryStatus => { /* ... */ },
///     EventType::DeviceEvent => { /* ... */ },
///     EventType::DeviceLifeCycle => { /* ... */ },
///     EventType::DeviceOta => { /* ... */ },
///     EventType::DeviceState => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `eventtype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `EventType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `EventType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `EventType::NewFeature` is defined.
/// Specifically, when `eventtype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `EventType::NewFeature` also yielding `"NewFeature"`.
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
pub enum EventType {
    #[allow(missing_docs)] // documentation missing in model
    AccountAssociation,
    #[allow(missing_docs)] // documentation missing in model
    #[deprecated]
    ConnectorAssociation,
    #[allow(missing_docs)] // documentation missing in model
    ConnectorErrorReport,
    #[allow(missing_docs)] // documentation missing in model
    DeviceCommand,
    #[allow(missing_docs)] // documentation missing in model
    DeviceCommandRequest,
    #[allow(missing_docs)] // documentation missing in model
    DeviceDiscoveryStatus,
    #[allow(missing_docs)] // documentation missing in model
    DeviceEvent,
    #[allow(missing_docs)] // documentation missing in model
    DeviceLifeCycle,
    #[allow(missing_docs)] // documentation missing in model
    DeviceOta,
    #[allow(missing_docs)] // documentation missing in model
    DeviceState,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for EventType {
    fn from(s: &str) -> Self {
        match s {
            "ACCOUNT_ASSOCIATION" => EventType::AccountAssociation,
            "CONNECTOR_ASSOCIATION" => EventType::ConnectorAssociation,
            "CONNECTOR_ERROR_REPORT" => EventType::ConnectorErrorReport,
            "DEVICE_COMMAND" => EventType::DeviceCommand,
            "DEVICE_COMMAND_REQUEST" => EventType::DeviceCommandRequest,
            "DEVICE_DISCOVERY_STATUS" => EventType::DeviceDiscoveryStatus,
            "DEVICE_EVENT" => EventType::DeviceEvent,
            "DEVICE_LIFE_CYCLE" => EventType::DeviceLifeCycle,
            "DEVICE_OTA" => EventType::DeviceOta,
            "DEVICE_STATE" => EventType::DeviceState,
            other => EventType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for EventType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(EventType::from(s))
    }
}
impl EventType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            EventType::AccountAssociation => "ACCOUNT_ASSOCIATION",
            EventType::ConnectorAssociation => "CONNECTOR_ASSOCIATION",
            EventType::ConnectorErrorReport => "CONNECTOR_ERROR_REPORT",
            EventType::DeviceCommand => "DEVICE_COMMAND",
            EventType::DeviceCommandRequest => "DEVICE_COMMAND_REQUEST",
            EventType::DeviceDiscoveryStatus => "DEVICE_DISCOVERY_STATUS",
            EventType::DeviceEvent => "DEVICE_EVENT",
            EventType::DeviceLifeCycle => "DEVICE_LIFE_CYCLE",
            EventType::DeviceOta => "DEVICE_OTA",
            EventType::DeviceState => "DEVICE_STATE",
            EventType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACCOUNT_ASSOCIATION",
            "CONNECTOR_ASSOCIATION",
            "CONNECTOR_ERROR_REPORT",
            "DEVICE_COMMAND",
            "DEVICE_COMMAND_REQUEST",
            "DEVICE_DISCOVERY_STATUS",
            "DEVICE_EVENT",
            "DEVICE_LIFE_CYCLE",
            "DEVICE_OTA",
            "DEVICE_STATE",
        ]
    }
}
impl ::std::convert::AsRef<str> for EventType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl EventType {
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
impl ::std::fmt::Display for EventType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            EventType::AccountAssociation => write!(f, "ACCOUNT_ASSOCIATION"),
            EventType::ConnectorAssociation => write!(f, "CONNECTOR_ASSOCIATION"),
            EventType::ConnectorErrorReport => write!(f, "CONNECTOR_ERROR_REPORT"),
            EventType::DeviceCommand => write!(f, "DEVICE_COMMAND"),
            EventType::DeviceCommandRequest => write!(f, "DEVICE_COMMAND_REQUEST"),
            EventType::DeviceDiscoveryStatus => write!(f, "DEVICE_DISCOVERY_STATUS"),
            EventType::DeviceEvent => write!(f, "DEVICE_EVENT"),
            EventType::DeviceLifeCycle => write!(f, "DEVICE_LIFE_CYCLE"),
            EventType::DeviceOta => write!(f, "DEVICE_OTA"),
            EventType::DeviceState => write!(f, "DEVICE_STATE"),
            EventType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
