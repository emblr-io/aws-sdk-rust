// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `KeyMaterialType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let keymaterialtype = unimplemented!();
/// match keymaterialtype {
///     KeyMaterialType::KeyCryptogram => { /* ... */ },
///     KeyMaterialType::RootPublicKeyCertificate => { /* ... */ },
///     KeyMaterialType::Tr31KeyBlock => { /* ... */ },
///     KeyMaterialType::Tr34KeyBlock => { /* ... */ },
///     KeyMaterialType::TrustedPublicKeyCertificate => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `keymaterialtype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `KeyMaterialType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `KeyMaterialType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `KeyMaterialType::NewFeature` is defined.
/// Specifically, when `keymaterialtype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `KeyMaterialType::NewFeature` also yielding `"NewFeature"`.
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
pub enum KeyMaterialType {
    #[allow(missing_docs)] // documentation missing in model
    KeyCryptogram,
    #[allow(missing_docs)] // documentation missing in model
    RootPublicKeyCertificate,
    #[allow(missing_docs)] // documentation missing in model
    Tr31KeyBlock,
    #[allow(missing_docs)] // documentation missing in model
    Tr34KeyBlock,
    #[allow(missing_docs)] // documentation missing in model
    TrustedPublicKeyCertificate,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for KeyMaterialType {
    fn from(s: &str) -> Self {
        match s {
            "KEY_CRYPTOGRAM" => KeyMaterialType::KeyCryptogram,
            "ROOT_PUBLIC_KEY_CERTIFICATE" => KeyMaterialType::RootPublicKeyCertificate,
            "TR31_KEY_BLOCK" => KeyMaterialType::Tr31KeyBlock,
            "TR34_KEY_BLOCK" => KeyMaterialType::Tr34KeyBlock,
            "TRUSTED_PUBLIC_KEY_CERTIFICATE" => KeyMaterialType::TrustedPublicKeyCertificate,
            other => KeyMaterialType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for KeyMaterialType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(KeyMaterialType::from(s))
    }
}
impl KeyMaterialType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            KeyMaterialType::KeyCryptogram => "KEY_CRYPTOGRAM",
            KeyMaterialType::RootPublicKeyCertificate => "ROOT_PUBLIC_KEY_CERTIFICATE",
            KeyMaterialType::Tr31KeyBlock => "TR31_KEY_BLOCK",
            KeyMaterialType::Tr34KeyBlock => "TR34_KEY_BLOCK",
            KeyMaterialType::TrustedPublicKeyCertificate => "TRUSTED_PUBLIC_KEY_CERTIFICATE",
            KeyMaterialType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "KEY_CRYPTOGRAM",
            "ROOT_PUBLIC_KEY_CERTIFICATE",
            "TR31_KEY_BLOCK",
            "TR34_KEY_BLOCK",
            "TRUSTED_PUBLIC_KEY_CERTIFICATE",
        ]
    }
}
impl ::std::convert::AsRef<str> for KeyMaterialType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl KeyMaterialType {
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
impl ::std::fmt::Display for KeyMaterialType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            KeyMaterialType::KeyCryptogram => write!(f, "KEY_CRYPTOGRAM"),
            KeyMaterialType::RootPublicKeyCertificate => write!(f, "ROOT_PUBLIC_KEY_CERTIFICATE"),
            KeyMaterialType::Tr31KeyBlock => write!(f, "TR31_KEY_BLOCK"),
            KeyMaterialType::Tr34KeyBlock => write!(f, "TR34_KEY_BLOCK"),
            KeyMaterialType::TrustedPublicKeyCertificate => write!(f, "TRUSTED_PUBLIC_KEY_CERTIFICATE"),
            KeyMaterialType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
