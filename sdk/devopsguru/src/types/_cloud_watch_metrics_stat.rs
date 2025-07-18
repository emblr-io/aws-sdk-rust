// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `CloudWatchMetricsStat`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let cloudwatchmetricsstat = unimplemented!();
/// match cloudwatchmetricsstat {
///     CloudWatchMetricsStat::Average => { /* ... */ },
///     CloudWatchMetricsStat::Maximum => { /* ... */ },
///     CloudWatchMetricsStat::Minimum => { /* ... */ },
///     CloudWatchMetricsStat::SampleCount => { /* ... */ },
///     CloudWatchMetricsStat::Sum => { /* ... */ },
///     CloudWatchMetricsStat::P50 => { /* ... */ },
///     CloudWatchMetricsStat::P90 => { /* ... */ },
///     CloudWatchMetricsStat::P99 => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `cloudwatchmetricsstat` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `CloudWatchMetricsStat::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `CloudWatchMetricsStat::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `CloudWatchMetricsStat::NewFeature` is defined.
/// Specifically, when `cloudwatchmetricsstat` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `CloudWatchMetricsStat::NewFeature` also yielding `"NewFeature"`.
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
pub enum CloudWatchMetricsStat {
    #[allow(missing_docs)] // documentation missing in model
    Average,
    #[allow(missing_docs)] // documentation missing in model
    Maximum,
    #[allow(missing_docs)] // documentation missing in model
    Minimum,
    #[allow(missing_docs)] // documentation missing in model
    SampleCount,
    #[allow(missing_docs)] // documentation missing in model
    Sum,
    #[allow(missing_docs)] // documentation missing in model
    P50,
    #[allow(missing_docs)] // documentation missing in model
    P90,
    #[allow(missing_docs)] // documentation missing in model
    P99,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for CloudWatchMetricsStat {
    fn from(s: &str) -> Self {
        match s {
            "Average" => CloudWatchMetricsStat::Average,
            "Maximum" => CloudWatchMetricsStat::Maximum,
            "Minimum" => CloudWatchMetricsStat::Minimum,
            "SampleCount" => CloudWatchMetricsStat::SampleCount,
            "Sum" => CloudWatchMetricsStat::Sum,
            "p50" => CloudWatchMetricsStat::P50,
            "p90" => CloudWatchMetricsStat::P90,
            "p99" => CloudWatchMetricsStat::P99,
            other => CloudWatchMetricsStat::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for CloudWatchMetricsStat {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(CloudWatchMetricsStat::from(s))
    }
}
impl CloudWatchMetricsStat {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            CloudWatchMetricsStat::Average => "Average",
            CloudWatchMetricsStat::Maximum => "Maximum",
            CloudWatchMetricsStat::Minimum => "Minimum",
            CloudWatchMetricsStat::SampleCount => "SampleCount",
            CloudWatchMetricsStat::Sum => "Sum",
            CloudWatchMetricsStat::P50 => "p50",
            CloudWatchMetricsStat::P90 => "p90",
            CloudWatchMetricsStat::P99 => "p99",
            CloudWatchMetricsStat::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["Average", "Maximum", "Minimum", "SampleCount", "Sum", "p50", "p90", "p99"]
    }
}
impl ::std::convert::AsRef<str> for CloudWatchMetricsStat {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl CloudWatchMetricsStat {
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
impl ::std::fmt::Display for CloudWatchMetricsStat {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            CloudWatchMetricsStat::Average => write!(f, "Average"),
            CloudWatchMetricsStat::Maximum => write!(f, "Maximum"),
            CloudWatchMetricsStat::Minimum => write!(f, "Minimum"),
            CloudWatchMetricsStat::SampleCount => write!(f, "SampleCount"),
            CloudWatchMetricsStat::Sum => write!(f, "Sum"),
            CloudWatchMetricsStat::P50 => write!(f, "p50"),
            CloudWatchMetricsStat::P90 => write!(f, "p90"),
            CloudWatchMetricsStat::P99 => write!(f, "p99"),
            CloudWatchMetricsStat::Unknown(value) => write!(f, "{}", value),
        }
    }
}
