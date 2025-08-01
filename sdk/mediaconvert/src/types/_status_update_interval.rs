// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `StatusUpdateInterval`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let statusupdateinterval = unimplemented!();
/// match statusupdateinterval {
///     StatusUpdateInterval::Seconds10 => { /* ... */ },
///     StatusUpdateInterval::Seconds12 => { /* ... */ },
///     StatusUpdateInterval::Seconds120 => { /* ... */ },
///     StatusUpdateInterval::Seconds15 => { /* ... */ },
///     StatusUpdateInterval::Seconds180 => { /* ... */ },
///     StatusUpdateInterval::Seconds20 => { /* ... */ },
///     StatusUpdateInterval::Seconds240 => { /* ... */ },
///     StatusUpdateInterval::Seconds30 => { /* ... */ },
///     StatusUpdateInterval::Seconds300 => { /* ... */ },
///     StatusUpdateInterval::Seconds360 => { /* ... */ },
///     StatusUpdateInterval::Seconds420 => { /* ... */ },
///     StatusUpdateInterval::Seconds480 => { /* ... */ },
///     StatusUpdateInterval::Seconds540 => { /* ... */ },
///     StatusUpdateInterval::Seconds60 => { /* ... */ },
///     StatusUpdateInterval::Seconds600 => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `statusupdateinterval` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `StatusUpdateInterval::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `StatusUpdateInterval::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `StatusUpdateInterval::NewFeature` is defined.
/// Specifically, when `statusupdateinterval` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `StatusUpdateInterval::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// Specify how often MediaConvert sends STATUS_UPDATE events to Amazon CloudWatch Events. Set the interval, in seconds, between status updates. MediaConvert sends an update at this interval from the time the service begins processing your job to the time it completes the transcode or encounters an error.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum StatusUpdateInterval {
    #[allow(missing_docs)] // documentation missing in model
    Seconds10,
    #[allow(missing_docs)] // documentation missing in model
    Seconds12,
    #[allow(missing_docs)] // documentation missing in model
    Seconds120,
    #[allow(missing_docs)] // documentation missing in model
    Seconds15,
    #[allow(missing_docs)] // documentation missing in model
    Seconds180,
    #[allow(missing_docs)] // documentation missing in model
    Seconds20,
    #[allow(missing_docs)] // documentation missing in model
    Seconds240,
    #[allow(missing_docs)] // documentation missing in model
    Seconds30,
    #[allow(missing_docs)] // documentation missing in model
    Seconds300,
    #[allow(missing_docs)] // documentation missing in model
    Seconds360,
    #[allow(missing_docs)] // documentation missing in model
    Seconds420,
    #[allow(missing_docs)] // documentation missing in model
    Seconds480,
    #[allow(missing_docs)] // documentation missing in model
    Seconds540,
    #[allow(missing_docs)] // documentation missing in model
    Seconds60,
    #[allow(missing_docs)] // documentation missing in model
    Seconds600,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for StatusUpdateInterval {
    fn from(s: &str) -> Self {
        match s {
            "SECONDS_10" => StatusUpdateInterval::Seconds10,
            "SECONDS_12" => StatusUpdateInterval::Seconds12,
            "SECONDS_120" => StatusUpdateInterval::Seconds120,
            "SECONDS_15" => StatusUpdateInterval::Seconds15,
            "SECONDS_180" => StatusUpdateInterval::Seconds180,
            "SECONDS_20" => StatusUpdateInterval::Seconds20,
            "SECONDS_240" => StatusUpdateInterval::Seconds240,
            "SECONDS_30" => StatusUpdateInterval::Seconds30,
            "SECONDS_300" => StatusUpdateInterval::Seconds300,
            "SECONDS_360" => StatusUpdateInterval::Seconds360,
            "SECONDS_420" => StatusUpdateInterval::Seconds420,
            "SECONDS_480" => StatusUpdateInterval::Seconds480,
            "SECONDS_540" => StatusUpdateInterval::Seconds540,
            "SECONDS_60" => StatusUpdateInterval::Seconds60,
            "SECONDS_600" => StatusUpdateInterval::Seconds600,
            other => StatusUpdateInterval::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for StatusUpdateInterval {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(StatusUpdateInterval::from(s))
    }
}
impl StatusUpdateInterval {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            StatusUpdateInterval::Seconds10 => "SECONDS_10",
            StatusUpdateInterval::Seconds12 => "SECONDS_12",
            StatusUpdateInterval::Seconds120 => "SECONDS_120",
            StatusUpdateInterval::Seconds15 => "SECONDS_15",
            StatusUpdateInterval::Seconds180 => "SECONDS_180",
            StatusUpdateInterval::Seconds20 => "SECONDS_20",
            StatusUpdateInterval::Seconds240 => "SECONDS_240",
            StatusUpdateInterval::Seconds30 => "SECONDS_30",
            StatusUpdateInterval::Seconds300 => "SECONDS_300",
            StatusUpdateInterval::Seconds360 => "SECONDS_360",
            StatusUpdateInterval::Seconds420 => "SECONDS_420",
            StatusUpdateInterval::Seconds480 => "SECONDS_480",
            StatusUpdateInterval::Seconds540 => "SECONDS_540",
            StatusUpdateInterval::Seconds60 => "SECONDS_60",
            StatusUpdateInterval::Seconds600 => "SECONDS_600",
            StatusUpdateInterval::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "SECONDS_10",
            "SECONDS_12",
            "SECONDS_120",
            "SECONDS_15",
            "SECONDS_180",
            "SECONDS_20",
            "SECONDS_240",
            "SECONDS_30",
            "SECONDS_300",
            "SECONDS_360",
            "SECONDS_420",
            "SECONDS_480",
            "SECONDS_540",
            "SECONDS_60",
            "SECONDS_600",
        ]
    }
}
impl ::std::convert::AsRef<str> for StatusUpdateInterval {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl StatusUpdateInterval {
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
impl ::std::fmt::Display for StatusUpdateInterval {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            StatusUpdateInterval::Seconds10 => write!(f, "SECONDS_10"),
            StatusUpdateInterval::Seconds12 => write!(f, "SECONDS_12"),
            StatusUpdateInterval::Seconds120 => write!(f, "SECONDS_120"),
            StatusUpdateInterval::Seconds15 => write!(f, "SECONDS_15"),
            StatusUpdateInterval::Seconds180 => write!(f, "SECONDS_180"),
            StatusUpdateInterval::Seconds20 => write!(f, "SECONDS_20"),
            StatusUpdateInterval::Seconds240 => write!(f, "SECONDS_240"),
            StatusUpdateInterval::Seconds30 => write!(f, "SECONDS_30"),
            StatusUpdateInterval::Seconds300 => write!(f, "SECONDS_300"),
            StatusUpdateInterval::Seconds360 => write!(f, "SECONDS_360"),
            StatusUpdateInterval::Seconds420 => write!(f, "SECONDS_420"),
            StatusUpdateInterval::Seconds480 => write!(f, "SECONDS_480"),
            StatusUpdateInterval::Seconds540 => write!(f, "SECONDS_540"),
            StatusUpdateInterval::Seconds60 => write!(f, "SECONDS_60"),
            StatusUpdateInterval::Seconds600 => write!(f, "SECONDS_600"),
            StatusUpdateInterval::Unknown(value) => write!(f, "{}", value),
        }
    }
}
