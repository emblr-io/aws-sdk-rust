// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `SchemaAttributeType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let schemaattributetype = unimplemented!();
/// match schemaattributetype {
///     SchemaAttributeType::Address => { /* ... */ },
///     SchemaAttributeType::AddressCity => { /* ... */ },
///     SchemaAttributeType::AddressCountry => { /* ... */ },
///     SchemaAttributeType::AddressPostalcode => { /* ... */ },
///     SchemaAttributeType::AddressState => { /* ... */ },
///     SchemaAttributeType::AddressStreet1 => { /* ... */ },
///     SchemaAttributeType::AddressStreet2 => { /* ... */ },
///     SchemaAttributeType::AddressStreet3 => { /* ... */ },
///     SchemaAttributeType::Date => { /* ... */ },
///     SchemaAttributeType::EmailAddress => { /* ... */ },
///     SchemaAttributeType::Ipv4 => { /* ... */ },
///     SchemaAttributeType::Ipv6 => { /* ... */ },
///     SchemaAttributeType::Maid => { /* ... */ },
///     SchemaAttributeType::Name => { /* ... */ },
///     SchemaAttributeType::NameFirst => { /* ... */ },
///     SchemaAttributeType::NameLast => { /* ... */ },
///     SchemaAttributeType::NameMiddle => { /* ... */ },
///     SchemaAttributeType::Phone => { /* ... */ },
///     SchemaAttributeType::PhoneCountrycode => { /* ... */ },
///     SchemaAttributeType::PhoneNumber => { /* ... */ },
///     SchemaAttributeType::ProviderId => { /* ... */ },
///     SchemaAttributeType::String => { /* ... */ },
///     SchemaAttributeType::UniqueId => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `schemaattributetype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `SchemaAttributeType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `SchemaAttributeType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `SchemaAttributeType::NewFeature` is defined.
/// Specifically, when `schemaattributetype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `SchemaAttributeType::NewFeature` also yielding `"NewFeature"`.
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
pub enum SchemaAttributeType {
    #[allow(missing_docs)] // documentation missing in model
    Address,
    #[allow(missing_docs)] // documentation missing in model
    AddressCity,
    #[allow(missing_docs)] // documentation missing in model
    AddressCountry,
    #[allow(missing_docs)] // documentation missing in model
    AddressPostalcode,
    #[allow(missing_docs)] // documentation missing in model
    AddressState,
    #[allow(missing_docs)] // documentation missing in model
    AddressStreet1,
    #[allow(missing_docs)] // documentation missing in model
    AddressStreet2,
    #[allow(missing_docs)] // documentation missing in model
    AddressStreet3,
    #[allow(missing_docs)] // documentation missing in model
    Date,
    #[allow(missing_docs)] // documentation missing in model
    EmailAddress,
    #[allow(missing_docs)] // documentation missing in model
    Ipv4,
    #[allow(missing_docs)] // documentation missing in model
    Ipv6,
    #[allow(missing_docs)] // documentation missing in model
    Maid,
    #[allow(missing_docs)] // documentation missing in model
    Name,
    #[allow(missing_docs)] // documentation missing in model
    NameFirst,
    #[allow(missing_docs)] // documentation missing in model
    NameLast,
    #[allow(missing_docs)] // documentation missing in model
    NameMiddle,
    #[allow(missing_docs)] // documentation missing in model
    Phone,
    #[allow(missing_docs)] // documentation missing in model
    PhoneCountrycode,
    #[allow(missing_docs)] // documentation missing in model
    PhoneNumber,
    #[allow(missing_docs)] // documentation missing in model
    ProviderId,
    #[allow(missing_docs)] // documentation missing in model
    String,
    #[allow(missing_docs)] // documentation missing in model
    UniqueId,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for SchemaAttributeType {
    fn from(s: &str) -> Self {
        match s {
            "ADDRESS" => SchemaAttributeType::Address,
            "ADDRESS_CITY" => SchemaAttributeType::AddressCity,
            "ADDRESS_COUNTRY" => SchemaAttributeType::AddressCountry,
            "ADDRESS_POSTALCODE" => SchemaAttributeType::AddressPostalcode,
            "ADDRESS_STATE" => SchemaAttributeType::AddressState,
            "ADDRESS_STREET1" => SchemaAttributeType::AddressStreet1,
            "ADDRESS_STREET2" => SchemaAttributeType::AddressStreet2,
            "ADDRESS_STREET3" => SchemaAttributeType::AddressStreet3,
            "DATE" => SchemaAttributeType::Date,
            "EMAIL_ADDRESS" => SchemaAttributeType::EmailAddress,
            "IPV4" => SchemaAttributeType::Ipv4,
            "IPV6" => SchemaAttributeType::Ipv6,
            "MAID" => SchemaAttributeType::Maid,
            "NAME" => SchemaAttributeType::Name,
            "NAME_FIRST" => SchemaAttributeType::NameFirst,
            "NAME_LAST" => SchemaAttributeType::NameLast,
            "NAME_MIDDLE" => SchemaAttributeType::NameMiddle,
            "PHONE" => SchemaAttributeType::Phone,
            "PHONE_COUNTRYCODE" => SchemaAttributeType::PhoneCountrycode,
            "PHONE_NUMBER" => SchemaAttributeType::PhoneNumber,
            "PROVIDER_ID" => SchemaAttributeType::ProviderId,
            "STRING" => SchemaAttributeType::String,
            "UNIQUE_ID" => SchemaAttributeType::UniqueId,
            other => SchemaAttributeType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for SchemaAttributeType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(SchemaAttributeType::from(s))
    }
}
impl SchemaAttributeType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            SchemaAttributeType::Address => "ADDRESS",
            SchemaAttributeType::AddressCity => "ADDRESS_CITY",
            SchemaAttributeType::AddressCountry => "ADDRESS_COUNTRY",
            SchemaAttributeType::AddressPostalcode => "ADDRESS_POSTALCODE",
            SchemaAttributeType::AddressState => "ADDRESS_STATE",
            SchemaAttributeType::AddressStreet1 => "ADDRESS_STREET1",
            SchemaAttributeType::AddressStreet2 => "ADDRESS_STREET2",
            SchemaAttributeType::AddressStreet3 => "ADDRESS_STREET3",
            SchemaAttributeType::Date => "DATE",
            SchemaAttributeType::EmailAddress => "EMAIL_ADDRESS",
            SchemaAttributeType::Ipv4 => "IPV4",
            SchemaAttributeType::Ipv6 => "IPV6",
            SchemaAttributeType::Maid => "MAID",
            SchemaAttributeType::Name => "NAME",
            SchemaAttributeType::NameFirst => "NAME_FIRST",
            SchemaAttributeType::NameLast => "NAME_LAST",
            SchemaAttributeType::NameMiddle => "NAME_MIDDLE",
            SchemaAttributeType::Phone => "PHONE",
            SchemaAttributeType::PhoneCountrycode => "PHONE_COUNTRYCODE",
            SchemaAttributeType::PhoneNumber => "PHONE_NUMBER",
            SchemaAttributeType::ProviderId => "PROVIDER_ID",
            SchemaAttributeType::String => "STRING",
            SchemaAttributeType::UniqueId => "UNIQUE_ID",
            SchemaAttributeType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ADDRESS",
            "ADDRESS_CITY",
            "ADDRESS_COUNTRY",
            "ADDRESS_POSTALCODE",
            "ADDRESS_STATE",
            "ADDRESS_STREET1",
            "ADDRESS_STREET2",
            "ADDRESS_STREET3",
            "DATE",
            "EMAIL_ADDRESS",
            "IPV4",
            "IPV6",
            "MAID",
            "NAME",
            "NAME_FIRST",
            "NAME_LAST",
            "NAME_MIDDLE",
            "PHONE",
            "PHONE_COUNTRYCODE",
            "PHONE_NUMBER",
            "PROVIDER_ID",
            "STRING",
            "UNIQUE_ID",
        ]
    }
}
impl ::std::convert::AsRef<str> for SchemaAttributeType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl SchemaAttributeType {
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
impl ::std::fmt::Display for SchemaAttributeType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            SchemaAttributeType::Address => write!(f, "ADDRESS"),
            SchemaAttributeType::AddressCity => write!(f, "ADDRESS_CITY"),
            SchemaAttributeType::AddressCountry => write!(f, "ADDRESS_COUNTRY"),
            SchemaAttributeType::AddressPostalcode => write!(f, "ADDRESS_POSTALCODE"),
            SchemaAttributeType::AddressState => write!(f, "ADDRESS_STATE"),
            SchemaAttributeType::AddressStreet1 => write!(f, "ADDRESS_STREET1"),
            SchemaAttributeType::AddressStreet2 => write!(f, "ADDRESS_STREET2"),
            SchemaAttributeType::AddressStreet3 => write!(f, "ADDRESS_STREET3"),
            SchemaAttributeType::Date => write!(f, "DATE"),
            SchemaAttributeType::EmailAddress => write!(f, "EMAIL_ADDRESS"),
            SchemaAttributeType::Ipv4 => write!(f, "IPV4"),
            SchemaAttributeType::Ipv6 => write!(f, "IPV6"),
            SchemaAttributeType::Maid => write!(f, "MAID"),
            SchemaAttributeType::Name => write!(f, "NAME"),
            SchemaAttributeType::NameFirst => write!(f, "NAME_FIRST"),
            SchemaAttributeType::NameLast => write!(f, "NAME_LAST"),
            SchemaAttributeType::NameMiddle => write!(f, "NAME_MIDDLE"),
            SchemaAttributeType::Phone => write!(f, "PHONE"),
            SchemaAttributeType::PhoneCountrycode => write!(f, "PHONE_COUNTRYCODE"),
            SchemaAttributeType::PhoneNumber => write!(f, "PHONE_NUMBER"),
            SchemaAttributeType::ProviderId => write!(f, "PROVIDER_ID"),
            SchemaAttributeType::String => write!(f, "STRING"),
            SchemaAttributeType::UniqueId => write!(f, "UNIQUE_ID"),
            SchemaAttributeType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
