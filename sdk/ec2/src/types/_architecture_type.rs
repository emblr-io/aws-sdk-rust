// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ArchitectureType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let architecturetype = unimplemented!();
/// match architecturetype {
///     ArchitectureType::Arm64 => { /* ... */ },
///     ArchitectureType::Arm64Mac => { /* ... */ },
///     ArchitectureType::I386 => { /* ... */ },
///     ArchitectureType::X8664 => { /* ... */ },
///     ArchitectureType::X8664Mac => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `architecturetype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ArchitectureType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ArchitectureType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ArchitectureType::NewFeature` is defined.
/// Specifically, when `architecturetype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ArchitectureType::NewFeature` also yielding `"NewFeature"`.
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
pub enum ArchitectureType {
    #[allow(missing_docs)] // documentation missing in model
    Arm64,
    #[allow(missing_docs)] // documentation missing in model
    Arm64Mac,
    #[allow(missing_docs)] // documentation missing in model
    I386,
    #[allow(missing_docs)] // documentation missing in model
    X8664,
    #[allow(missing_docs)] // documentation missing in model
    X8664Mac,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ArchitectureType {
    fn from(s: &str) -> Self {
        match s {
            "arm64" => ArchitectureType::Arm64,
            "arm64_mac" => ArchitectureType::Arm64Mac,
            "i386" => ArchitectureType::I386,
            "x86_64" => ArchitectureType::X8664,
            "x86_64_mac" => ArchitectureType::X8664Mac,
            other => ArchitectureType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ArchitectureType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ArchitectureType::from(s))
    }
}
impl ArchitectureType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ArchitectureType::Arm64 => "arm64",
            ArchitectureType::Arm64Mac => "arm64_mac",
            ArchitectureType::I386 => "i386",
            ArchitectureType::X8664 => "x86_64",
            ArchitectureType::X8664Mac => "x86_64_mac",
            ArchitectureType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["arm64", "arm64_mac", "i386", "x86_64", "x86_64_mac"]
    }
}
impl ::std::convert::AsRef<str> for ArchitectureType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ArchitectureType {
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
impl ::std::fmt::Display for ArchitectureType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ArchitectureType::Arm64 => write!(f, "arm64"),
            ArchitectureType::Arm64Mac => write!(f, "arm64_mac"),
            ArchitectureType::I386 => write!(f, "i386"),
            ArchitectureType::X8664 => write!(f, "x86_64"),
            ArchitectureType::X8664Mac => write!(f, "x86_64_mac"),
            ArchitectureType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
