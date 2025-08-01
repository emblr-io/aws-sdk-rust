// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AttributeDimensionType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let attributedimensiontype = unimplemented!();
/// match attributedimensiontype {
///     AttributeDimensionType::After => { /* ... */ },
///     AttributeDimensionType::Before => { /* ... */ },
///     AttributeDimensionType::BeginsWith => { /* ... */ },
///     AttributeDimensionType::Between => { /* ... */ },
///     AttributeDimensionType::Contains => { /* ... */ },
///     AttributeDimensionType::EndsWith => { /* ... */ },
///     AttributeDimensionType::Equal => { /* ... */ },
///     AttributeDimensionType::Exclusive => { /* ... */ },
///     AttributeDimensionType::GreaterThan => { /* ... */ },
///     AttributeDimensionType::GreaterThanOrEqual => { /* ... */ },
///     AttributeDimensionType::Inclusive => { /* ... */ },
///     AttributeDimensionType::LessThan => { /* ... */ },
///     AttributeDimensionType::LessThanOrEqual => { /* ... */ },
///     AttributeDimensionType::NotBetween => { /* ... */ },
///     AttributeDimensionType::On => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `attributedimensiontype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AttributeDimensionType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AttributeDimensionType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AttributeDimensionType::NewFeature` is defined.
/// Specifically, when `attributedimensiontype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AttributeDimensionType::NewFeature` also yielding `"NewFeature"`.
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
pub enum AttributeDimensionType {
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
impl ::std::convert::From<&str> for AttributeDimensionType {
    fn from(s: &str) -> Self {
        match s {
            "AFTER" => AttributeDimensionType::After,
            "BEFORE" => AttributeDimensionType::Before,
            "BEGINS_WITH" => AttributeDimensionType::BeginsWith,
            "BETWEEN" => AttributeDimensionType::Between,
            "CONTAINS" => AttributeDimensionType::Contains,
            "ENDS_WITH" => AttributeDimensionType::EndsWith,
            "EQUAL" => AttributeDimensionType::Equal,
            "EXCLUSIVE" => AttributeDimensionType::Exclusive,
            "GREATER_THAN" => AttributeDimensionType::GreaterThan,
            "GREATER_THAN_OR_EQUAL" => AttributeDimensionType::GreaterThanOrEqual,
            "INCLUSIVE" => AttributeDimensionType::Inclusive,
            "LESS_THAN" => AttributeDimensionType::LessThan,
            "LESS_THAN_OR_EQUAL" => AttributeDimensionType::LessThanOrEqual,
            "NOT_BETWEEN" => AttributeDimensionType::NotBetween,
            "ON" => AttributeDimensionType::On,
            other => AttributeDimensionType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AttributeDimensionType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AttributeDimensionType::from(s))
    }
}
impl AttributeDimensionType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AttributeDimensionType::After => "AFTER",
            AttributeDimensionType::Before => "BEFORE",
            AttributeDimensionType::BeginsWith => "BEGINS_WITH",
            AttributeDimensionType::Between => "BETWEEN",
            AttributeDimensionType::Contains => "CONTAINS",
            AttributeDimensionType::EndsWith => "ENDS_WITH",
            AttributeDimensionType::Equal => "EQUAL",
            AttributeDimensionType::Exclusive => "EXCLUSIVE",
            AttributeDimensionType::GreaterThan => "GREATER_THAN",
            AttributeDimensionType::GreaterThanOrEqual => "GREATER_THAN_OR_EQUAL",
            AttributeDimensionType::Inclusive => "INCLUSIVE",
            AttributeDimensionType::LessThan => "LESS_THAN",
            AttributeDimensionType::LessThanOrEqual => "LESS_THAN_OR_EQUAL",
            AttributeDimensionType::NotBetween => "NOT_BETWEEN",
            AttributeDimensionType::On => "ON",
            AttributeDimensionType::Unknown(value) => value.as_str(),
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
impl ::std::convert::AsRef<str> for AttributeDimensionType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AttributeDimensionType {
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
impl ::std::fmt::Display for AttributeDimensionType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AttributeDimensionType::After => write!(f, "AFTER"),
            AttributeDimensionType::Before => write!(f, "BEFORE"),
            AttributeDimensionType::BeginsWith => write!(f, "BEGINS_WITH"),
            AttributeDimensionType::Between => write!(f, "BETWEEN"),
            AttributeDimensionType::Contains => write!(f, "CONTAINS"),
            AttributeDimensionType::EndsWith => write!(f, "ENDS_WITH"),
            AttributeDimensionType::Equal => write!(f, "EQUAL"),
            AttributeDimensionType::Exclusive => write!(f, "EXCLUSIVE"),
            AttributeDimensionType::GreaterThan => write!(f, "GREATER_THAN"),
            AttributeDimensionType::GreaterThanOrEqual => write!(f, "GREATER_THAN_OR_EQUAL"),
            AttributeDimensionType::Inclusive => write!(f, "INCLUSIVE"),
            AttributeDimensionType::LessThan => write!(f, "LESS_THAN"),
            AttributeDimensionType::LessThanOrEqual => write!(f, "LESS_THAN_OR_EQUAL"),
            AttributeDimensionType::NotBetween => write!(f, "NOT_BETWEEN"),
            AttributeDimensionType::On => write!(f, "ON"),
            AttributeDimensionType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
