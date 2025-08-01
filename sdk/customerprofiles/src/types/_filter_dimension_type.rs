// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `FilterDimensionType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let filterdimensiontype = unimplemented!();
/// match filterdimensiontype {
///     FilterDimensionType::After => { /* ... */ },
///     FilterDimensionType::Before => { /* ... */ },
///     FilterDimensionType::BeginsWith => { /* ... */ },
///     FilterDimensionType::Between => { /* ... */ },
///     FilterDimensionType::Contains => { /* ... */ },
///     FilterDimensionType::EndsWith => { /* ... */ },
///     FilterDimensionType::Equal => { /* ... */ },
///     FilterDimensionType::Exclusive => { /* ... */ },
///     FilterDimensionType::GreaterThan => { /* ... */ },
///     FilterDimensionType::GreaterThanOrEqual => { /* ... */ },
///     FilterDimensionType::Inclusive => { /* ... */ },
///     FilterDimensionType::LessThan => { /* ... */ },
///     FilterDimensionType::LessThanOrEqual => { /* ... */ },
///     FilterDimensionType::NotBetween => { /* ... */ },
///     FilterDimensionType::On => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `filterdimensiontype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `FilterDimensionType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `FilterDimensionType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `FilterDimensionType::NewFeature` is defined.
/// Specifically, when `filterdimensiontype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `FilterDimensionType::NewFeature` also yielding `"NewFeature"`.
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
pub enum FilterDimensionType {
    #[allow(missing_docs)] // documentation missing in model
    After,
    #[allow(missing_docs)] // documentation missing in model
    Before,
    #[allow(missing_docs)] // documentation missing in model
    BeginsWith,
    #[allow(missing_docs)] // documentation missing in model
    Between,
    #[allow(missing_docs)] // documentation missing in model
    Contains,
    #[allow(missing_docs)] // documentation missing in model
    EndsWith,
    #[allow(missing_docs)] // documentation missing in model
    Equal,
    #[allow(missing_docs)] // documentation missing in model
    Exclusive,
    #[allow(missing_docs)] // documentation missing in model
    GreaterThan,
    #[allow(missing_docs)] // documentation missing in model
    GreaterThanOrEqual,
    #[allow(missing_docs)] // documentation missing in model
    Inclusive,
    #[allow(missing_docs)] // documentation missing in model
    LessThan,
    #[allow(missing_docs)] // documentation missing in model
    LessThanOrEqual,
    #[allow(missing_docs)] // documentation missing in model
    NotBetween,
    #[allow(missing_docs)] // documentation missing in model
    On,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for FilterDimensionType {
    fn from(s: &str) -> Self {
        match s {
            "AFTER" => FilterDimensionType::After,
            "BEFORE" => FilterDimensionType::Before,
            "BEGINS_WITH" => FilterDimensionType::BeginsWith,
            "BETWEEN" => FilterDimensionType::Between,
            "CONTAINS" => FilterDimensionType::Contains,
            "ENDS_WITH" => FilterDimensionType::EndsWith,
            "EQUAL" => FilterDimensionType::Equal,
            "EXCLUSIVE" => FilterDimensionType::Exclusive,
            "GREATER_THAN" => FilterDimensionType::GreaterThan,
            "GREATER_THAN_OR_EQUAL" => FilterDimensionType::GreaterThanOrEqual,
            "INCLUSIVE" => FilterDimensionType::Inclusive,
            "LESS_THAN" => FilterDimensionType::LessThan,
            "LESS_THAN_OR_EQUAL" => FilterDimensionType::LessThanOrEqual,
            "NOT_BETWEEN" => FilterDimensionType::NotBetween,
            "ON" => FilterDimensionType::On,
            other => FilterDimensionType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for FilterDimensionType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(FilterDimensionType::from(s))
    }
}
impl FilterDimensionType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            FilterDimensionType::After => "AFTER",
            FilterDimensionType::Before => "BEFORE",
            FilterDimensionType::BeginsWith => "BEGINS_WITH",
            FilterDimensionType::Between => "BETWEEN",
            FilterDimensionType::Contains => "CONTAINS",
            FilterDimensionType::EndsWith => "ENDS_WITH",
            FilterDimensionType::Equal => "EQUAL",
            FilterDimensionType::Exclusive => "EXCLUSIVE",
            FilterDimensionType::GreaterThan => "GREATER_THAN",
            FilterDimensionType::GreaterThanOrEqual => "GREATER_THAN_OR_EQUAL",
            FilterDimensionType::Inclusive => "INCLUSIVE",
            FilterDimensionType::LessThan => "LESS_THAN",
            FilterDimensionType::LessThanOrEqual => "LESS_THAN_OR_EQUAL",
            FilterDimensionType::NotBetween => "NOT_BETWEEN",
            FilterDimensionType::On => "ON",
            FilterDimensionType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AFTER",
            "BEFORE",
            "BEGINS_WITH",
            "BETWEEN",
            "CONTAINS",
            "ENDS_WITH",
            "EQUAL",
            "EXCLUSIVE",
            "GREATER_THAN",
            "GREATER_THAN_OR_EQUAL",
            "INCLUSIVE",
            "LESS_THAN",
            "LESS_THAN_OR_EQUAL",
            "NOT_BETWEEN",
            "ON",
        ]
    }
}
impl ::std::convert::AsRef<str> for FilterDimensionType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl FilterDimensionType {
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
impl ::std::fmt::Display for FilterDimensionType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            FilterDimensionType::After => write!(f, "AFTER"),
            FilterDimensionType::Before => write!(f, "BEFORE"),
            FilterDimensionType::BeginsWith => write!(f, "BEGINS_WITH"),
            FilterDimensionType::Between => write!(f, "BETWEEN"),
            FilterDimensionType::Contains => write!(f, "CONTAINS"),
            FilterDimensionType::EndsWith => write!(f, "ENDS_WITH"),
            FilterDimensionType::Equal => write!(f, "EQUAL"),
            FilterDimensionType::Exclusive => write!(f, "EXCLUSIVE"),
            FilterDimensionType::GreaterThan => write!(f, "GREATER_THAN"),
            FilterDimensionType::GreaterThanOrEqual => write!(f, "GREATER_THAN_OR_EQUAL"),
            FilterDimensionType::Inclusive => write!(f, "INCLUSIVE"),
            FilterDimensionType::LessThan => write!(f, "LESS_THAN"),
            FilterDimensionType::LessThanOrEqual => write!(f, "LESS_THAN_OR_EQUAL"),
            FilterDimensionType::NotBetween => write!(f, "NOT_BETWEEN"),
            FilterDimensionType::On => write!(f, "ON"),
            FilterDimensionType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
