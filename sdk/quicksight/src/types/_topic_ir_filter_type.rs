// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `TopicIrFilterType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let topicirfiltertype = unimplemented!();
/// match topicirfiltertype {
///     TopicIrFilterType::AcceptAllFilter => { /* ... */ },
///     TopicIrFilterType::CategoryFilter => { /* ... */ },
///     TopicIrFilterType::DateRangeFilter => { /* ... */ },
///     TopicIrFilterType::Equals => { /* ... */ },
///     TopicIrFilterType::NumericEqualityFilter => { /* ... */ },
///     TopicIrFilterType::NumericRangeFilter => { /* ... */ },
///     TopicIrFilterType::RankLimitFilter => { /* ... */ },
///     TopicIrFilterType::RelativeDateFilter => { /* ... */ },
///     TopicIrFilterType::TopBottomFilter => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `topicirfiltertype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `TopicIrFilterType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `TopicIrFilterType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `TopicIrFilterType::NewFeature` is defined.
/// Specifically, when `topicirfiltertype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `TopicIrFilterType::NewFeature` also yielding `"NewFeature"`.
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
pub enum TopicIrFilterType {
    #[allow(missing_docs)] // documentation missing in model
    AcceptAllFilter,
    #[allow(missing_docs)] // documentation missing in model
    CategoryFilter,
    #[allow(missing_docs)] // documentation missing in model
    DateRangeFilter,
    #[allow(missing_docs)] // documentation missing in model
    Equals,
    #[allow(missing_docs)] // documentation missing in model
    NumericEqualityFilter,
    #[allow(missing_docs)] // documentation missing in model
    NumericRangeFilter,
    #[allow(missing_docs)] // documentation missing in model
    RankLimitFilter,
    #[allow(missing_docs)] // documentation missing in model
    RelativeDateFilter,
    #[allow(missing_docs)] // documentation missing in model
    TopBottomFilter,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for TopicIrFilterType {
    fn from(s: &str) -> Self {
        match s {
            "ACCEPT_ALL_FILTER" => TopicIrFilterType::AcceptAllFilter,
            "CATEGORY_FILTER" => TopicIrFilterType::CategoryFilter,
            "DATE_RANGE_FILTER" => TopicIrFilterType::DateRangeFilter,
            "EQUALS" => TopicIrFilterType::Equals,
            "NUMERIC_EQUALITY_FILTER" => TopicIrFilterType::NumericEqualityFilter,
            "NUMERIC_RANGE_FILTER" => TopicIrFilterType::NumericRangeFilter,
            "RANK_LIMIT_FILTER" => TopicIrFilterType::RankLimitFilter,
            "RELATIVE_DATE_FILTER" => TopicIrFilterType::RelativeDateFilter,
            "TOP_BOTTOM_FILTER" => TopicIrFilterType::TopBottomFilter,
            other => TopicIrFilterType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for TopicIrFilterType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(TopicIrFilterType::from(s))
    }
}
impl TopicIrFilterType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            TopicIrFilterType::AcceptAllFilter => "ACCEPT_ALL_FILTER",
            TopicIrFilterType::CategoryFilter => "CATEGORY_FILTER",
            TopicIrFilterType::DateRangeFilter => "DATE_RANGE_FILTER",
            TopicIrFilterType::Equals => "EQUALS",
            TopicIrFilterType::NumericEqualityFilter => "NUMERIC_EQUALITY_FILTER",
            TopicIrFilterType::NumericRangeFilter => "NUMERIC_RANGE_FILTER",
            TopicIrFilterType::RankLimitFilter => "RANK_LIMIT_FILTER",
            TopicIrFilterType::RelativeDateFilter => "RELATIVE_DATE_FILTER",
            TopicIrFilterType::TopBottomFilter => "TOP_BOTTOM_FILTER",
            TopicIrFilterType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACCEPT_ALL_FILTER",
            "CATEGORY_FILTER",
            "DATE_RANGE_FILTER",
            "EQUALS",
            "NUMERIC_EQUALITY_FILTER",
            "NUMERIC_RANGE_FILTER",
            "RANK_LIMIT_FILTER",
            "RELATIVE_DATE_FILTER",
            "TOP_BOTTOM_FILTER",
        ]
    }
}
impl ::std::convert::AsRef<str> for TopicIrFilterType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl TopicIrFilterType {
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
impl ::std::fmt::Display for TopicIrFilterType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            TopicIrFilterType::AcceptAllFilter => write!(f, "ACCEPT_ALL_FILTER"),
            TopicIrFilterType::CategoryFilter => write!(f, "CATEGORY_FILTER"),
            TopicIrFilterType::DateRangeFilter => write!(f, "DATE_RANGE_FILTER"),
            TopicIrFilterType::Equals => write!(f, "EQUALS"),
            TopicIrFilterType::NumericEqualityFilter => write!(f, "NUMERIC_EQUALITY_FILTER"),
            TopicIrFilterType::NumericRangeFilter => write!(f, "NUMERIC_RANGE_FILTER"),
            TopicIrFilterType::RankLimitFilter => write!(f, "RANK_LIMIT_FILTER"),
            TopicIrFilterType::RelativeDateFilter => write!(f, "RELATIVE_DATE_FILTER"),
            TopicIrFilterType::TopBottomFilter => write!(f, "TOP_BOTTOM_FILTER"),
            TopicIrFilterType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
