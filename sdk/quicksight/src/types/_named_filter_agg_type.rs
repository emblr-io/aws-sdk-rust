// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `NamedFilterAggType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let namedfilteraggtype = unimplemented!();
/// match namedfilteraggtype {
///     NamedFilterAggType::Average => { /* ... */ },
///     NamedFilterAggType::Count => { /* ... */ },
///     NamedFilterAggType::DistinctCount => { /* ... */ },
///     NamedFilterAggType::Max => { /* ... */ },
///     NamedFilterAggType::Median => { /* ... */ },
///     NamedFilterAggType::Min => { /* ... */ },
///     NamedFilterAggType::NoAggregation => { /* ... */ },
///     NamedFilterAggType::Stdev => { /* ... */ },
///     NamedFilterAggType::Stdevp => { /* ... */ },
///     NamedFilterAggType::Sum => { /* ... */ },
///     NamedFilterAggType::Var => { /* ... */ },
///     NamedFilterAggType::Varp => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `namedfilteraggtype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `NamedFilterAggType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `NamedFilterAggType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `NamedFilterAggType::NewFeature` is defined.
/// Specifically, when `namedfilteraggtype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `NamedFilterAggType::NewFeature` also yielding `"NewFeature"`.
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
pub enum NamedFilterAggType {
    #[allow(missing_docs)] // documentation missing in model
    Average,
    #[allow(missing_docs)] // documentation missing in model
    Count,
    #[allow(missing_docs)] // documentation missing in model
    DistinctCount,
    #[allow(missing_docs)] // documentation missing in model
    Max,
    #[allow(missing_docs)] // documentation missing in model
    Median,
    #[allow(missing_docs)] // documentation missing in model
    Min,
    #[allow(missing_docs)] // documentation missing in model
    NoAggregation,
    #[allow(missing_docs)] // documentation missing in model
    Stdev,
    #[allow(missing_docs)] // documentation missing in model
    Stdevp,
    #[allow(missing_docs)] // documentation missing in model
    Sum,
    #[allow(missing_docs)] // documentation missing in model
    Var,
    #[allow(missing_docs)] // documentation missing in model
    Varp,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for NamedFilterAggType {
    fn from(s: &str) -> Self {
        match s {
            "AVERAGE" => NamedFilterAggType::Average,
            "COUNT" => NamedFilterAggType::Count,
            "DISTINCT_COUNT" => NamedFilterAggType::DistinctCount,
            "MAX" => NamedFilterAggType::Max,
            "MEDIAN" => NamedFilterAggType::Median,
            "MIN" => NamedFilterAggType::Min,
            "NO_AGGREGATION" => NamedFilterAggType::NoAggregation,
            "STDEV" => NamedFilterAggType::Stdev,
            "STDEVP" => NamedFilterAggType::Stdevp,
            "SUM" => NamedFilterAggType::Sum,
            "VAR" => NamedFilterAggType::Var,
            "VARP" => NamedFilterAggType::Varp,
            other => NamedFilterAggType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for NamedFilterAggType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(NamedFilterAggType::from(s))
    }
}
impl NamedFilterAggType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            NamedFilterAggType::Average => "AVERAGE",
            NamedFilterAggType::Count => "COUNT",
            NamedFilterAggType::DistinctCount => "DISTINCT_COUNT",
            NamedFilterAggType::Max => "MAX",
            NamedFilterAggType::Median => "MEDIAN",
            NamedFilterAggType::Min => "MIN",
            NamedFilterAggType::NoAggregation => "NO_AGGREGATION",
            NamedFilterAggType::Stdev => "STDEV",
            NamedFilterAggType::Stdevp => "STDEVP",
            NamedFilterAggType::Sum => "SUM",
            NamedFilterAggType::Var => "VAR",
            NamedFilterAggType::Varp => "VARP",
            NamedFilterAggType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AVERAGE",
            "COUNT",
            "DISTINCT_COUNT",
            "MAX",
            "MEDIAN",
            "MIN",
            "NO_AGGREGATION",
            "STDEV",
            "STDEVP",
            "SUM",
            "VAR",
            "VARP",
        ]
    }
}
impl ::std::convert::AsRef<str> for NamedFilterAggType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl NamedFilterAggType {
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
impl ::std::fmt::Display for NamedFilterAggType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            NamedFilterAggType::Average => write!(f, "AVERAGE"),
            NamedFilterAggType::Count => write!(f, "COUNT"),
            NamedFilterAggType::DistinctCount => write!(f, "DISTINCT_COUNT"),
            NamedFilterAggType::Max => write!(f, "MAX"),
            NamedFilterAggType::Median => write!(f, "MEDIAN"),
            NamedFilterAggType::Min => write!(f, "MIN"),
            NamedFilterAggType::NoAggregation => write!(f, "NO_AGGREGATION"),
            NamedFilterAggType::Stdev => write!(f, "STDEV"),
            NamedFilterAggType::Stdevp => write!(f, "STDEVP"),
            NamedFilterAggType::Sum => write!(f, "SUM"),
            NamedFilterAggType::Var => write!(f, "VAR"),
            NamedFilterAggType::Varp => write!(f, "VARP"),
            NamedFilterAggType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
