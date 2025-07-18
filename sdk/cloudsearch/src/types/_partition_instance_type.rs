// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `PartitionInstanceType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let partitioninstancetype = unimplemented!();
/// match partitioninstancetype {
///     PartitionInstanceType::Search2xlarge => { /* ... */ },
///     PartitionInstanceType::SearchLarge => { /* ... */ },
///     PartitionInstanceType::SearchM1Large => { /* ... */ },
///     PartitionInstanceType::SearchM1Small => { /* ... */ },
///     PartitionInstanceType::SearchM22xlarge => { /* ... */ },
///     PartitionInstanceType::SearchM2Xlarge => { /* ... */ },
///     PartitionInstanceType::SearchM32xlarge => { /* ... */ },
///     PartitionInstanceType::SearchM3Large => { /* ... */ },
///     PartitionInstanceType::SearchM3Medium => { /* ... */ },
///     PartitionInstanceType::SearchM3Xlarge => { /* ... */ },
///     PartitionInstanceType::SearchMedium => { /* ... */ },
///     PartitionInstanceType::SearchPreviousgeneration2xlarge => { /* ... */ },
///     PartitionInstanceType::SearchPreviousgenerationLarge => { /* ... */ },
///     PartitionInstanceType::SearchPreviousgenerationSmall => { /* ... */ },
///     PartitionInstanceType::SearchPreviousgenerationXlarge => { /* ... */ },
///     PartitionInstanceType::SearchSmall => { /* ... */ },
///     PartitionInstanceType::SearchXlarge => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `partitioninstancetype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `PartitionInstanceType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `PartitionInstanceType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `PartitionInstanceType::NewFeature` is defined.
/// Specifically, when `partitioninstancetype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `PartitionInstanceType::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// <p>The instance type (such as <code>search.m1.small</code>) on which an index partition is hosted.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum PartitionInstanceType {
    #[allow(missing_docs)] // documentation missing in model
    Search2xlarge,
    #[allow(missing_docs)] // documentation missing in model
    SearchLarge,
    #[allow(missing_docs)] // documentation missing in model
    SearchM1Large,
    #[allow(missing_docs)] // documentation missing in model
    SearchM1Small,
    #[allow(missing_docs)] // documentation missing in model
    SearchM22xlarge,
    #[allow(missing_docs)] // documentation missing in model
    SearchM2Xlarge,
    #[allow(missing_docs)] // documentation missing in model
    SearchM32xlarge,
    #[allow(missing_docs)] // documentation missing in model
    SearchM3Large,
    #[allow(missing_docs)] // documentation missing in model
    SearchM3Medium,
    #[allow(missing_docs)] // documentation missing in model
    SearchM3Xlarge,
    #[allow(missing_docs)] // documentation missing in model
    SearchMedium,
    #[allow(missing_docs)] // documentation missing in model
    SearchPreviousgeneration2xlarge,
    #[allow(missing_docs)] // documentation missing in model
    SearchPreviousgenerationLarge,
    #[allow(missing_docs)] // documentation missing in model
    SearchPreviousgenerationSmall,
    #[allow(missing_docs)] // documentation missing in model
    SearchPreviousgenerationXlarge,
    #[allow(missing_docs)] // documentation missing in model
    SearchSmall,
    #[allow(missing_docs)] // documentation missing in model
    SearchXlarge,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for PartitionInstanceType {
    fn from(s: &str) -> Self {
        match s {
            "search.2xlarge" => PartitionInstanceType::Search2xlarge,
            "search.large" => PartitionInstanceType::SearchLarge,
            "search.m1.large" => PartitionInstanceType::SearchM1Large,
            "search.m1.small" => PartitionInstanceType::SearchM1Small,
            "search.m2.2xlarge" => PartitionInstanceType::SearchM22xlarge,
            "search.m2.xlarge" => PartitionInstanceType::SearchM2Xlarge,
            "search.m3.2xlarge" => PartitionInstanceType::SearchM32xlarge,
            "search.m3.large" => PartitionInstanceType::SearchM3Large,
            "search.m3.medium" => PartitionInstanceType::SearchM3Medium,
            "search.m3.xlarge" => PartitionInstanceType::SearchM3Xlarge,
            "search.medium" => PartitionInstanceType::SearchMedium,
            "search.previousgeneration.2xlarge" => PartitionInstanceType::SearchPreviousgeneration2xlarge,
            "search.previousgeneration.large" => PartitionInstanceType::SearchPreviousgenerationLarge,
            "search.previousgeneration.small" => PartitionInstanceType::SearchPreviousgenerationSmall,
            "search.previousgeneration.xlarge" => PartitionInstanceType::SearchPreviousgenerationXlarge,
            "search.small" => PartitionInstanceType::SearchSmall,
            "search.xlarge" => PartitionInstanceType::SearchXlarge,
            other => PartitionInstanceType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for PartitionInstanceType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(PartitionInstanceType::from(s))
    }
}
impl PartitionInstanceType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            PartitionInstanceType::Search2xlarge => "search.2xlarge",
            PartitionInstanceType::SearchLarge => "search.large",
            PartitionInstanceType::SearchM1Large => "search.m1.large",
            PartitionInstanceType::SearchM1Small => "search.m1.small",
            PartitionInstanceType::SearchM22xlarge => "search.m2.2xlarge",
            PartitionInstanceType::SearchM2Xlarge => "search.m2.xlarge",
            PartitionInstanceType::SearchM32xlarge => "search.m3.2xlarge",
            PartitionInstanceType::SearchM3Large => "search.m3.large",
            PartitionInstanceType::SearchM3Medium => "search.m3.medium",
            PartitionInstanceType::SearchM3Xlarge => "search.m3.xlarge",
            PartitionInstanceType::SearchMedium => "search.medium",
            PartitionInstanceType::SearchPreviousgeneration2xlarge => "search.previousgeneration.2xlarge",
            PartitionInstanceType::SearchPreviousgenerationLarge => "search.previousgeneration.large",
            PartitionInstanceType::SearchPreviousgenerationSmall => "search.previousgeneration.small",
            PartitionInstanceType::SearchPreviousgenerationXlarge => "search.previousgeneration.xlarge",
            PartitionInstanceType::SearchSmall => "search.small",
            PartitionInstanceType::SearchXlarge => "search.xlarge",
            PartitionInstanceType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "search.2xlarge",
            "search.large",
            "search.m1.large",
            "search.m1.small",
            "search.m2.2xlarge",
            "search.m2.xlarge",
            "search.m3.2xlarge",
            "search.m3.large",
            "search.m3.medium",
            "search.m3.xlarge",
            "search.medium",
            "search.previousgeneration.2xlarge",
            "search.previousgeneration.large",
            "search.previousgeneration.small",
            "search.previousgeneration.xlarge",
            "search.small",
            "search.xlarge",
        ]
    }
}
impl ::std::convert::AsRef<str> for PartitionInstanceType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl PartitionInstanceType {
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
impl ::std::fmt::Display for PartitionInstanceType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PartitionInstanceType::Search2xlarge => write!(f, "search.2xlarge"),
            PartitionInstanceType::SearchLarge => write!(f, "search.large"),
            PartitionInstanceType::SearchM1Large => write!(f, "search.m1.large"),
            PartitionInstanceType::SearchM1Small => write!(f, "search.m1.small"),
            PartitionInstanceType::SearchM22xlarge => write!(f, "search.m2.2xlarge"),
            PartitionInstanceType::SearchM2Xlarge => write!(f, "search.m2.xlarge"),
            PartitionInstanceType::SearchM32xlarge => write!(f, "search.m3.2xlarge"),
            PartitionInstanceType::SearchM3Large => write!(f, "search.m3.large"),
            PartitionInstanceType::SearchM3Medium => write!(f, "search.m3.medium"),
            PartitionInstanceType::SearchM3Xlarge => write!(f, "search.m3.xlarge"),
            PartitionInstanceType::SearchMedium => write!(f, "search.medium"),
            PartitionInstanceType::SearchPreviousgeneration2xlarge => write!(f, "search.previousgeneration.2xlarge"),
            PartitionInstanceType::SearchPreviousgenerationLarge => write!(f, "search.previousgeneration.large"),
            PartitionInstanceType::SearchPreviousgenerationSmall => write!(f, "search.previousgeneration.small"),
            PartitionInstanceType::SearchPreviousgenerationXlarge => write!(f, "search.previousgeneration.xlarge"),
            PartitionInstanceType::SearchSmall => write!(f, "search.small"),
            PartitionInstanceType::SearchXlarge => write!(f, "search.xlarge"),
            PartitionInstanceType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
