// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `Compute`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let compute = unimplemented!();
/// match compute {
///     Compute::Generalpurpose4Xlarge => { /* ... */ },
///     Compute::Generalpurpose8Xlarge => { /* ... */ },
///     Compute::Graphics => { /* ... */ },
///     Compute::Graphicspro => { /* ... */ },
///     Compute::GraphicsproG4Dn => { /* ... */ },
///     Compute::GraphicsG4Dn => { /* ... */ },
///     Compute::Performance => { /* ... */ },
///     Compute::Power => { /* ... */ },
///     Compute::Powerpro => { /* ... */ },
///     Compute::Standard => { /* ... */ },
///     Compute::Value => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `compute` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `Compute::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `Compute::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `Compute::NewFeature` is defined.
/// Specifically, when `compute` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `Compute::NewFeature` also yielding `"NewFeature"`.
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
pub enum Compute {
    #[allow(missing_docs)] // documentation missing in model
    Generalpurpose4Xlarge,
    #[allow(missing_docs)] // documentation missing in model
    Generalpurpose8Xlarge,
    #[allow(missing_docs)] // documentation missing in model
    Graphics,
    #[allow(missing_docs)] // documentation missing in model
    Graphicspro,
    #[allow(missing_docs)] // documentation missing in model
    GraphicsproG4Dn,
    #[allow(missing_docs)] // documentation missing in model
    GraphicsG4Dn,
    #[allow(missing_docs)] // documentation missing in model
    Performance,
    #[allow(missing_docs)] // documentation missing in model
    Power,
    #[allow(missing_docs)] // documentation missing in model
    Powerpro,
    #[allow(missing_docs)] // documentation missing in model
    Standard,
    #[allow(missing_docs)] // documentation missing in model
    Value,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for Compute {
    fn from(s: &str) -> Self {
        match s {
            "GENERALPURPOSE_4XLARGE" => Compute::Generalpurpose4Xlarge,
            "GENERALPURPOSE_8XLARGE" => Compute::Generalpurpose8Xlarge,
            "GRAPHICS" => Compute::Graphics,
            "GRAPHICSPRO" => Compute::Graphicspro,
            "GRAPHICSPRO_G4DN" => Compute::GraphicsproG4Dn,
            "GRAPHICS_G4DN" => Compute::GraphicsG4Dn,
            "PERFORMANCE" => Compute::Performance,
            "POWER" => Compute::Power,
            "POWERPRO" => Compute::Powerpro,
            "STANDARD" => Compute::Standard,
            "VALUE" => Compute::Value,
            other => Compute::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for Compute {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(Compute::from(s))
    }
}
impl Compute {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            Compute::Generalpurpose4Xlarge => "GENERALPURPOSE_4XLARGE",
            Compute::Generalpurpose8Xlarge => "GENERALPURPOSE_8XLARGE",
            Compute::Graphics => "GRAPHICS",
            Compute::Graphicspro => "GRAPHICSPRO",
            Compute::GraphicsproG4Dn => "GRAPHICSPRO_G4DN",
            Compute::GraphicsG4Dn => "GRAPHICS_G4DN",
            Compute::Performance => "PERFORMANCE",
            Compute::Power => "POWER",
            Compute::Powerpro => "POWERPRO",
            Compute::Standard => "STANDARD",
            Compute::Value => "VALUE",
            Compute::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "GENERALPURPOSE_4XLARGE",
            "GENERALPURPOSE_8XLARGE",
            "GRAPHICS",
            "GRAPHICSPRO",
            "GRAPHICSPRO_G4DN",
            "GRAPHICS_G4DN",
            "PERFORMANCE",
            "POWER",
            "POWERPRO",
            "STANDARD",
            "VALUE",
        ]
    }
}
impl ::std::convert::AsRef<str> for Compute {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Compute {
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
impl ::std::fmt::Display for Compute {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Compute::Generalpurpose4Xlarge => write!(f, "GENERALPURPOSE_4XLARGE"),
            Compute::Generalpurpose8Xlarge => write!(f, "GENERALPURPOSE_8XLARGE"),
            Compute::Graphics => write!(f, "GRAPHICS"),
            Compute::Graphicspro => write!(f, "GRAPHICSPRO"),
            Compute::GraphicsproG4Dn => write!(f, "GRAPHICSPRO_G4DN"),
            Compute::GraphicsG4Dn => write!(f, "GRAPHICS_G4DN"),
            Compute::Performance => write!(f, "PERFORMANCE"),
            Compute::Power => write!(f, "POWER"),
            Compute::Powerpro => write!(f, "POWERPRO"),
            Compute::Standard => write!(f, "STANDARD"),
            Compute::Value => write!(f, "VALUE"),
            Compute::Unknown(value) => write!(f, "{}", value),
        }
    }
}
