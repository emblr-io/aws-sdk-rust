// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `H264CodecLevel`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let h264codeclevel = unimplemented!();
/// match h264codeclevel {
///     H264CodecLevel::Auto => { /* ... */ },
///     H264CodecLevel::Level1 => { /* ... */ },
///     H264CodecLevel::Level11 => { /* ... */ },
///     H264CodecLevel::Level12 => { /* ... */ },
///     H264CodecLevel::Level13 => { /* ... */ },
///     H264CodecLevel::Level2 => { /* ... */ },
///     H264CodecLevel::Level21 => { /* ... */ },
///     H264CodecLevel::Level22 => { /* ... */ },
///     H264CodecLevel::Level3 => { /* ... */ },
///     H264CodecLevel::Level31 => { /* ... */ },
///     H264CodecLevel::Level32 => { /* ... */ },
///     H264CodecLevel::Level4 => { /* ... */ },
///     H264CodecLevel::Level41 => { /* ... */ },
///     H264CodecLevel::Level42 => { /* ... */ },
///     H264CodecLevel::Level5 => { /* ... */ },
///     H264CodecLevel::Level51 => { /* ... */ },
///     H264CodecLevel::Level52 => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `h264codeclevel` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `H264CodecLevel::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `H264CodecLevel::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `H264CodecLevel::NewFeature` is defined.
/// Specifically, when `h264codeclevel` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `H264CodecLevel::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Specify an H.264 level that is consistent with your output video settings. If you aren't sure what level to specify, choose Auto.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum H264CodecLevel {
    #[allow(missing_docs)] // documentation missing in model
    Auto,
    #[allow(missing_docs)] // documentation missing in model
    Level1,
    #[allow(missing_docs)] // documentation missing in model
    Level11,
    #[allow(missing_docs)] // documentation missing in model
    Level12,
    #[allow(missing_docs)] // documentation missing in model
    Level13,
    #[allow(missing_docs)] // documentation missing in model
    Level2,
    #[allow(missing_docs)] // documentation missing in model
    Level21,
    #[allow(missing_docs)] // documentation missing in model
    Level22,
    #[allow(missing_docs)] // documentation missing in model
    Level3,
    #[allow(missing_docs)] // documentation missing in model
    Level31,
    #[allow(missing_docs)] // documentation missing in model
    Level32,
    #[allow(missing_docs)] // documentation missing in model
    Level4,
    #[allow(missing_docs)] // documentation missing in model
    Level41,
    #[allow(missing_docs)] // documentation missing in model
    Level42,
    #[allow(missing_docs)] // documentation missing in model
    Level5,
    #[allow(missing_docs)] // documentation missing in model
    Level51,
    #[allow(missing_docs)] // documentation missing in model
    Level52,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for H264CodecLevel {
    fn from(s: &str) -> Self {
        match s {
            "AUTO" => H264CodecLevel::Auto,
            "LEVEL_1" => H264CodecLevel::Level1,
            "LEVEL_1_1" => H264CodecLevel::Level11,
            "LEVEL_1_2" => H264CodecLevel::Level12,
            "LEVEL_1_3" => H264CodecLevel::Level13,
            "LEVEL_2" => H264CodecLevel::Level2,
            "LEVEL_2_1" => H264CodecLevel::Level21,
            "LEVEL_2_2" => H264CodecLevel::Level22,
            "LEVEL_3" => H264CodecLevel::Level3,
            "LEVEL_3_1" => H264CodecLevel::Level31,
            "LEVEL_3_2" => H264CodecLevel::Level32,
            "LEVEL_4" => H264CodecLevel::Level4,
            "LEVEL_4_1" => H264CodecLevel::Level41,
            "LEVEL_4_2" => H264CodecLevel::Level42,
            "LEVEL_5" => H264CodecLevel::Level5,
            "LEVEL_5_1" => H264CodecLevel::Level51,
            "LEVEL_5_2" => H264CodecLevel::Level52,
            other => H264CodecLevel::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for H264CodecLevel {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(H264CodecLevel::from(s))
    }
}
impl H264CodecLevel {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            H264CodecLevel::Auto => "AUTO",
            H264CodecLevel::Level1 => "LEVEL_1",
            H264CodecLevel::Level11 => "LEVEL_1_1",
            H264CodecLevel::Level12 => "LEVEL_1_2",
            H264CodecLevel::Level13 => "LEVEL_1_3",
            H264CodecLevel::Level2 => "LEVEL_2",
            H264CodecLevel::Level21 => "LEVEL_2_1",
            H264CodecLevel::Level22 => "LEVEL_2_2",
            H264CodecLevel::Level3 => "LEVEL_3",
            H264CodecLevel::Level31 => "LEVEL_3_1",
            H264CodecLevel::Level32 => "LEVEL_3_2",
            H264CodecLevel::Level4 => "LEVEL_4",
            H264CodecLevel::Level41 => "LEVEL_4_1",
            H264CodecLevel::Level42 => "LEVEL_4_2",
            H264CodecLevel::Level5 => "LEVEL_5",
            H264CodecLevel::Level51 => "LEVEL_5_1",
            H264CodecLevel::Level52 => "LEVEL_5_2",
            H264CodecLevel::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AUTO",
            "LEVEL_1",
            "LEVEL_1_1",
            "LEVEL_1_2",
            "LEVEL_1_3",
            "LEVEL_2",
            "LEVEL_2_1",
            "LEVEL_2_2",
            "LEVEL_3",
            "LEVEL_3_1",
            "LEVEL_3_2",
            "LEVEL_4",
            "LEVEL_4_1",
            "LEVEL_4_2",
            "LEVEL_5",
            "LEVEL_5_1",
            "LEVEL_5_2",
        ]
    }
}
impl ::std::convert::AsRef<str> for H264CodecLevel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl H264CodecLevel {
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
impl ::std::fmt::Display for H264CodecLevel {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            H264CodecLevel::Auto => write!(f, "AUTO"),
            H264CodecLevel::Level1 => write!(f, "LEVEL_1"),
            H264CodecLevel::Level11 => write!(f, "LEVEL_1_1"),
            H264CodecLevel::Level12 => write!(f, "LEVEL_1_2"),
            H264CodecLevel::Level13 => write!(f, "LEVEL_1_3"),
            H264CodecLevel::Level2 => write!(f, "LEVEL_2"),
            H264CodecLevel::Level21 => write!(f, "LEVEL_2_1"),
            H264CodecLevel::Level22 => write!(f, "LEVEL_2_2"),
            H264CodecLevel::Level3 => write!(f, "LEVEL_3"),
            H264CodecLevel::Level31 => write!(f, "LEVEL_3_1"),
            H264CodecLevel::Level32 => write!(f, "LEVEL_3_2"),
            H264CodecLevel::Level4 => write!(f, "LEVEL_4"),
            H264CodecLevel::Level41 => write!(f, "LEVEL_4_1"),
            H264CodecLevel::Level42 => write!(f, "LEVEL_4_2"),
            H264CodecLevel::Level5 => write!(f, "LEVEL_5"),
            H264CodecLevel::Level51 => write!(f, "LEVEL_5_1"),
            H264CodecLevel::Level52 => write!(f, "LEVEL_5_2"),
            H264CodecLevel::Unknown(value) => write!(f, "{}", value),
        }
    }
}
