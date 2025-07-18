// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `UplinkGbps`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let uplinkgbps = unimplemented!();
/// match uplinkgbps {
///     UplinkGbps::Uplink100G => { /* ... */ },
///     UplinkGbps::Uplink10G => { /* ... */ },
///     UplinkGbps::Uplink1G => { /* ... */ },
///     UplinkGbps::Uplink40G => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `uplinkgbps` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `UplinkGbps::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `UplinkGbps::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `UplinkGbps::NewFeature` is defined.
/// Specifically, when `uplinkgbps` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `UplinkGbps::NewFeature` also yielding `"NewFeature"`.
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
pub enum UplinkGbps {
    #[allow(missing_docs)] // documentation missing in model
    Uplink100G,
    #[allow(missing_docs)] // documentation missing in model
    Uplink10G,
    #[allow(missing_docs)] // documentation missing in model
    Uplink1G,
    #[allow(missing_docs)] // documentation missing in model
    Uplink40G,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for UplinkGbps {
    fn from(s: &str) -> Self {
        match s {
            "UPLINK_100G" => UplinkGbps::Uplink100G,
            "UPLINK_10G" => UplinkGbps::Uplink10G,
            "UPLINK_1G" => UplinkGbps::Uplink1G,
            "UPLINK_40G" => UplinkGbps::Uplink40G,
            other => UplinkGbps::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for UplinkGbps {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(UplinkGbps::from(s))
    }
}
impl UplinkGbps {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            UplinkGbps::Uplink100G => "UPLINK_100G",
            UplinkGbps::Uplink10G => "UPLINK_10G",
            UplinkGbps::Uplink1G => "UPLINK_1G",
            UplinkGbps::Uplink40G => "UPLINK_40G",
            UplinkGbps::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["UPLINK_100G", "UPLINK_10G", "UPLINK_1G", "UPLINK_40G"]
    }
}
impl ::std::convert::AsRef<str> for UplinkGbps {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl UplinkGbps {
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
impl ::std::fmt::Display for UplinkGbps {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            UplinkGbps::Uplink100G => write!(f, "UPLINK_100G"),
            UplinkGbps::Uplink10G => write!(f, "UPLINK_10G"),
            UplinkGbps::Uplink1G => write!(f, "UPLINK_1G"),
            UplinkGbps::Uplink40G => write!(f, "UPLINK_40G"),
            UplinkGbps::Unknown(value) => write!(f, "{}", value),
        }
    }
}
