// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `TargetPlatformArch`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let targetplatformarch = unimplemented!();
/// match targetplatformarch {
///     TargetPlatformArch::Arm64 => { /* ... */ },
///     TargetPlatformArch::ArmEabi => { /* ... */ },
///     TargetPlatformArch::ArmEabihf => { /* ... */ },
///     TargetPlatformArch::X86 => { /* ... */ },
///     TargetPlatformArch::X8664 => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `targetplatformarch` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `TargetPlatformArch::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `TargetPlatformArch::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `TargetPlatformArch::NewFeature` is defined.
/// Specifically, when `targetplatformarch` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `TargetPlatformArch::NewFeature` also yielding `"NewFeature"`.
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
pub enum TargetPlatformArch {
    #[allow(missing_docs)] // documentation missing in model
    Arm64,
    #[allow(missing_docs)] // documentation missing in model
    ArmEabi,
    #[allow(missing_docs)] // documentation missing in model
    ArmEabihf,
    #[allow(missing_docs)] // documentation missing in model
    X86,
    #[allow(missing_docs)] // documentation missing in model
    X8664,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for TargetPlatformArch {
    fn from(s: &str) -> Self {
        match s {
            "ARM64" => TargetPlatformArch::Arm64,
            "ARM_EABI" => TargetPlatformArch::ArmEabi,
            "ARM_EABIHF" => TargetPlatformArch::ArmEabihf,
            "X86" => TargetPlatformArch::X86,
            "X86_64" => TargetPlatformArch::X8664,
            other => TargetPlatformArch::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for TargetPlatformArch {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(TargetPlatformArch::from(s))
    }
}
impl TargetPlatformArch {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            TargetPlatformArch::Arm64 => "ARM64",
            TargetPlatformArch::ArmEabi => "ARM_EABI",
            TargetPlatformArch::ArmEabihf => "ARM_EABIHF",
            TargetPlatformArch::X86 => "X86",
            TargetPlatformArch::X8664 => "X86_64",
            TargetPlatformArch::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["ARM64", "ARM_EABI", "ARM_EABIHF", "X86", "X86_64"]
    }
}
impl ::std::convert::AsRef<str> for TargetPlatformArch {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl TargetPlatformArch {
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
impl ::std::fmt::Display for TargetPlatformArch {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            TargetPlatformArch::Arm64 => write!(f, "ARM64"),
            TargetPlatformArch::ArmEabi => write!(f, "ARM_EABI"),
            TargetPlatformArch::ArmEabihf => write!(f, "ARM_EABIHF"),
            TargetPlatformArch::X86 => write!(f, "X86"),
            TargetPlatformArch::X8664 => write!(f, "X86_64"),
            TargetPlatformArch::Unknown(value) => write!(f, "{}", value),
        }
    }
}
