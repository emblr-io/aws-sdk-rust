// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `WrappingKeySpec`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let wrappingkeyspec = unimplemented!();
/// match wrappingkeyspec {
///     WrappingKeySpec::Rsa2048 => { /* ... */ },
///     WrappingKeySpec::Rsa3072 => { /* ... */ },
///     WrappingKeySpec::Rsa4096 => { /* ... */ },
///     WrappingKeySpec::Sm2 => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `wrappingkeyspec` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `WrappingKeySpec::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `WrappingKeySpec::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `WrappingKeySpec::NewFeature` is defined.
/// Specifically, when `wrappingkeyspec` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `WrappingKeySpec::NewFeature` also yielding `"NewFeature"`.
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
pub enum WrappingKeySpec {
    #[allow(missing_docs)] // documentation missing in model
    Rsa2048,
    #[allow(missing_docs)] // documentation missing in model
    Rsa3072,
    #[allow(missing_docs)] // documentation missing in model
    Rsa4096,
    #[allow(missing_docs)] // documentation missing in model
    Sm2,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for WrappingKeySpec {
    fn from(s: &str) -> Self {
        match s {
            "RSA_2048" => WrappingKeySpec::Rsa2048,
            "RSA_3072" => WrappingKeySpec::Rsa3072,
            "RSA_4096" => WrappingKeySpec::Rsa4096,
            "SM2" => WrappingKeySpec::Sm2,
            other => WrappingKeySpec::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for WrappingKeySpec {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(WrappingKeySpec::from(s))
    }
}
impl WrappingKeySpec {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            WrappingKeySpec::Rsa2048 => "RSA_2048",
            WrappingKeySpec::Rsa3072 => "RSA_3072",
            WrappingKeySpec::Rsa4096 => "RSA_4096",
            WrappingKeySpec::Sm2 => "SM2",
            WrappingKeySpec::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["RSA_2048", "RSA_3072", "RSA_4096", "SM2"]
    }
}
impl ::std::convert::AsRef<str> for WrappingKeySpec {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl WrappingKeySpec {
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
impl ::std::fmt::Display for WrappingKeySpec {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            WrappingKeySpec::Rsa2048 => write!(f, "RSA_2048"),
            WrappingKeySpec::Rsa3072 => write!(f, "RSA_3072"),
            WrappingKeySpec::Rsa4096 => write!(f, "RSA_4096"),
            WrappingKeySpec::Sm2 => write!(f, "SM2"),
            WrappingKeySpec::Unknown(value) => write!(f, "{}", value),
        }
    }
}
