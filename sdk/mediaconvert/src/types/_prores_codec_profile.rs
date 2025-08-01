// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ProresCodecProfile`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let prorescodecprofile = unimplemented!();
/// match prorescodecprofile {
///     ProresCodecProfile::AppleProres422 => { /* ... */ },
///     ProresCodecProfile::AppleProres422Hq => { /* ... */ },
///     ProresCodecProfile::AppleProres422Lt => { /* ... */ },
///     ProresCodecProfile::AppleProres422Proxy => { /* ... */ },
///     ProresCodecProfile::AppleProres4444 => { /* ... */ },
///     ProresCodecProfile::AppleProres4444Xq => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `prorescodecprofile` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ProresCodecProfile::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ProresCodecProfile::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ProresCodecProfile::NewFeature` is defined.
/// Specifically, when `prorescodecprofile` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ProresCodecProfile::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Use Profile to specify the type of Apple ProRes codec to use for this output.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum ProresCodecProfile {
    #[allow(missing_docs)] // documentation missing in model
    AppleProres422,
    #[allow(missing_docs)] // documentation missing in model
    AppleProres422Hq,
    #[allow(missing_docs)] // documentation missing in model
    AppleProres422Lt,
    #[allow(missing_docs)] // documentation missing in model
    AppleProres422Proxy,
    #[allow(missing_docs)] // documentation missing in model
    AppleProres4444,
    #[allow(missing_docs)] // documentation missing in model
    AppleProres4444Xq,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ProresCodecProfile {
    fn from(s: &str) -> Self {
        match s {
            "APPLE_PRORES_422" => ProresCodecProfile::AppleProres422,
            "APPLE_PRORES_422_HQ" => ProresCodecProfile::AppleProres422Hq,
            "APPLE_PRORES_422_LT" => ProresCodecProfile::AppleProres422Lt,
            "APPLE_PRORES_422_PROXY" => ProresCodecProfile::AppleProres422Proxy,
            "APPLE_PRORES_4444" => ProresCodecProfile::AppleProres4444,
            "APPLE_PRORES_4444_XQ" => ProresCodecProfile::AppleProres4444Xq,
            other => ProresCodecProfile::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ProresCodecProfile {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ProresCodecProfile::from(s))
    }
}
impl ProresCodecProfile {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ProresCodecProfile::AppleProres422 => "APPLE_PRORES_422",
            ProresCodecProfile::AppleProres422Hq => "APPLE_PRORES_422_HQ",
            ProresCodecProfile::AppleProres422Lt => "APPLE_PRORES_422_LT",
            ProresCodecProfile::AppleProres422Proxy => "APPLE_PRORES_422_PROXY",
            ProresCodecProfile::AppleProres4444 => "APPLE_PRORES_4444",
            ProresCodecProfile::AppleProres4444Xq => "APPLE_PRORES_4444_XQ",
            ProresCodecProfile::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "APPLE_PRORES_422",
            "APPLE_PRORES_422_HQ",
            "APPLE_PRORES_422_LT",
            "APPLE_PRORES_422_PROXY",
            "APPLE_PRORES_4444",
            "APPLE_PRORES_4444_XQ",
        ]
    }
}
impl ::std::convert::AsRef<str> for ProresCodecProfile {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ProresCodecProfile {
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
impl ::std::fmt::Display for ProresCodecProfile {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ProresCodecProfile::AppleProres422 => write!(f, "APPLE_PRORES_422"),
            ProresCodecProfile::AppleProres422Hq => write!(f, "APPLE_PRORES_422_HQ"),
            ProresCodecProfile::AppleProres422Lt => write!(f, "APPLE_PRORES_422_LT"),
            ProresCodecProfile::AppleProres422Proxy => write!(f, "APPLE_PRORES_422_PROXY"),
            ProresCodecProfile::AppleProres4444 => write!(f, "APPLE_PRORES_4444"),
            ProresCodecProfile::AppleProres4444Xq => write!(f, "APPLE_PRORES_4444_XQ"),
            ProresCodecProfile::Unknown(value) => write!(f, "{}", value),
        }
    }
}
