// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AlgorithmSpec`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let algorithmspec = unimplemented!();
/// match algorithmspec {
///     AlgorithmSpec::RsaesOaepSha1 => { /* ... */ },
///     AlgorithmSpec::RsaesOaepSha256 => { /* ... */ },
///     AlgorithmSpec::RsaesPkcs1V15 => { /* ... */ },
///     AlgorithmSpec::RsaAesKeyWrapSha1 => { /* ... */ },
///     AlgorithmSpec::RsaAesKeyWrapSha256 => { /* ... */ },
///     AlgorithmSpec::Sm2Pke => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `algorithmspec` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AlgorithmSpec::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AlgorithmSpec::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AlgorithmSpec::NewFeature` is defined.
/// Specifically, when `algorithmspec` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AlgorithmSpec::NewFeature` also yielding `"NewFeature"`.
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
pub enum AlgorithmSpec {
    #[allow(missing_docs)] // documentation missing in model
    RsaesOaepSha1,
    #[allow(missing_docs)] // documentation missing in model
    RsaesOaepSha256,
    #[allow(missing_docs)] // documentation missing in model
    RsaesPkcs1V15,
    #[allow(missing_docs)] // documentation missing in model
    RsaAesKeyWrapSha1,
    #[allow(missing_docs)] // documentation missing in model
    RsaAesKeyWrapSha256,
    #[allow(missing_docs)] // documentation missing in model
    Sm2Pke,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AlgorithmSpec {
    fn from(s: &str) -> Self {
        match s {
            "RSAES_OAEP_SHA_1" => AlgorithmSpec::RsaesOaepSha1,
            "RSAES_OAEP_SHA_256" => AlgorithmSpec::RsaesOaepSha256,
            "RSAES_PKCS1_V1_5" => AlgorithmSpec::RsaesPkcs1V15,
            "RSA_AES_KEY_WRAP_SHA_1" => AlgorithmSpec::RsaAesKeyWrapSha1,
            "RSA_AES_KEY_WRAP_SHA_256" => AlgorithmSpec::RsaAesKeyWrapSha256,
            "SM2PKE" => AlgorithmSpec::Sm2Pke,
            other => AlgorithmSpec::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AlgorithmSpec {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AlgorithmSpec::from(s))
    }
}
impl AlgorithmSpec {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AlgorithmSpec::RsaesOaepSha1 => "RSAES_OAEP_SHA_1",
            AlgorithmSpec::RsaesOaepSha256 => "RSAES_OAEP_SHA_256",
            AlgorithmSpec::RsaesPkcs1V15 => "RSAES_PKCS1_V1_5",
            AlgorithmSpec::RsaAesKeyWrapSha1 => "RSA_AES_KEY_WRAP_SHA_1",
            AlgorithmSpec::RsaAesKeyWrapSha256 => "RSA_AES_KEY_WRAP_SHA_256",
            AlgorithmSpec::Sm2Pke => "SM2PKE",
            AlgorithmSpec::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "RSAES_OAEP_SHA_1",
            "RSAES_OAEP_SHA_256",
            "RSAES_PKCS1_V1_5",
            "RSA_AES_KEY_WRAP_SHA_1",
            "RSA_AES_KEY_WRAP_SHA_256",
            "SM2PKE",
        ]
    }
}
impl ::std::convert::AsRef<str> for AlgorithmSpec {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AlgorithmSpec {
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
impl ::std::fmt::Display for AlgorithmSpec {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AlgorithmSpec::RsaesOaepSha1 => write!(f, "RSAES_OAEP_SHA_1"),
            AlgorithmSpec::RsaesOaepSha256 => write!(f, "RSAES_OAEP_SHA_256"),
            AlgorithmSpec::RsaesPkcs1V15 => write!(f, "RSAES_PKCS1_V1_5"),
            AlgorithmSpec::RsaAesKeyWrapSha1 => write!(f, "RSA_AES_KEY_WRAP_SHA_1"),
            AlgorithmSpec::RsaAesKeyWrapSha256 => write!(f, "RSA_AES_KEY_WRAP_SHA_256"),
            AlgorithmSpec::Sm2Pke => write!(f, "SM2PKE"),
            AlgorithmSpec::Unknown(value) => write!(f, "{}", value),
        }
    }
}
