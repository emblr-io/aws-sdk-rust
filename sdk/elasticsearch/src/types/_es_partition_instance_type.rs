// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `EsPartitionInstanceType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let espartitioninstancetype = unimplemented!();
/// match espartitioninstancetype {
///     EsPartitionInstanceType::C42xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C44xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C48xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C4LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C4XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C518xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C52xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C54xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C59xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C5LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::C5XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::D22xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::D24xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::D28xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::D2XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::I22xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::I2XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::I316xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::I32xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::I34xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::I38xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::I3LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::I3XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M32xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M3LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M3MediumElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M3XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M410xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M42xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M44xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M4LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M4XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M512xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M52xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M54xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M5LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::M5XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R32xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R34xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R38xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R3LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R3XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R416xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R42xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R44xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R48xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R4LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R4XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R512xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R52xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R54xlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R5LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::R5XlargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::T2MediumElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::T2MicroElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::T2SmallElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::Ultrawarm1LargeElasticsearch => { /* ... */ },
///     EsPartitionInstanceType::Ultrawarm1MediumElasticsearch => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `espartitioninstancetype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `EsPartitionInstanceType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `EsPartitionInstanceType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `EsPartitionInstanceType::NewFeature` is defined.
/// Specifically, when `espartitioninstancetype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `EsPartitionInstanceType::NewFeature` also yielding `"NewFeature"`.
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
pub enum EsPartitionInstanceType {
    #[allow(missing_docs)] // documentation missing in model
    C42xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C44xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C48xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C4LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C4XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C518xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C52xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C54xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C59xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C5LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    C5XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    D22xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    D24xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    D28xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    D2XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    I22xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    I2XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    I316xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    I32xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    I34xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    I38xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    I3LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    I3XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M32xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M3LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M3MediumElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M3XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M410xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M42xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M44xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M4LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M4XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M512xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M52xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M54xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M5LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    M5XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R32xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R34xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R38xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R3LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R3XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R416xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R42xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R44xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R48xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R4LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R4XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R512xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R52xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R54xlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R5LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    R5XlargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    T2MediumElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    T2MicroElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    T2SmallElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    Ultrawarm1LargeElasticsearch,
    #[allow(missing_docs)] // documentation missing in model
    Ultrawarm1MediumElasticsearch,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for EsPartitionInstanceType {
    fn from(s: &str) -> Self {
        match s {
            "c4.2xlarge.elasticsearch" => EsPartitionInstanceType::C42xlargeElasticsearch,
            "c4.4xlarge.elasticsearch" => EsPartitionInstanceType::C44xlargeElasticsearch,
            "c4.8xlarge.elasticsearch" => EsPartitionInstanceType::C48xlargeElasticsearch,
            "c4.large.elasticsearch" => EsPartitionInstanceType::C4LargeElasticsearch,
            "c4.xlarge.elasticsearch" => EsPartitionInstanceType::C4XlargeElasticsearch,
            "c5.18xlarge.elasticsearch" => EsPartitionInstanceType::C518xlargeElasticsearch,
            "c5.2xlarge.elasticsearch" => EsPartitionInstanceType::C52xlargeElasticsearch,
            "c5.4xlarge.elasticsearch" => EsPartitionInstanceType::C54xlargeElasticsearch,
            "c5.9xlarge.elasticsearch" => EsPartitionInstanceType::C59xlargeElasticsearch,
            "c5.large.elasticsearch" => EsPartitionInstanceType::C5LargeElasticsearch,
            "c5.xlarge.elasticsearch" => EsPartitionInstanceType::C5XlargeElasticsearch,
            "d2.2xlarge.elasticsearch" => EsPartitionInstanceType::D22xlargeElasticsearch,
            "d2.4xlarge.elasticsearch" => EsPartitionInstanceType::D24xlargeElasticsearch,
            "d2.8xlarge.elasticsearch" => EsPartitionInstanceType::D28xlargeElasticsearch,
            "d2.xlarge.elasticsearch" => EsPartitionInstanceType::D2XlargeElasticsearch,
            "i2.2xlarge.elasticsearch" => EsPartitionInstanceType::I22xlargeElasticsearch,
            "i2.xlarge.elasticsearch" => EsPartitionInstanceType::I2XlargeElasticsearch,
            "i3.16xlarge.elasticsearch" => EsPartitionInstanceType::I316xlargeElasticsearch,
            "i3.2xlarge.elasticsearch" => EsPartitionInstanceType::I32xlargeElasticsearch,
            "i3.4xlarge.elasticsearch" => EsPartitionInstanceType::I34xlargeElasticsearch,
            "i3.8xlarge.elasticsearch" => EsPartitionInstanceType::I38xlargeElasticsearch,
            "i3.large.elasticsearch" => EsPartitionInstanceType::I3LargeElasticsearch,
            "i3.xlarge.elasticsearch" => EsPartitionInstanceType::I3XlargeElasticsearch,
            "m3.2xlarge.elasticsearch" => EsPartitionInstanceType::M32xlargeElasticsearch,
            "m3.large.elasticsearch" => EsPartitionInstanceType::M3LargeElasticsearch,
            "m3.medium.elasticsearch" => EsPartitionInstanceType::M3MediumElasticsearch,
            "m3.xlarge.elasticsearch" => EsPartitionInstanceType::M3XlargeElasticsearch,
            "m4.10xlarge.elasticsearch" => EsPartitionInstanceType::M410xlargeElasticsearch,
            "m4.2xlarge.elasticsearch" => EsPartitionInstanceType::M42xlargeElasticsearch,
            "m4.4xlarge.elasticsearch" => EsPartitionInstanceType::M44xlargeElasticsearch,
            "m4.large.elasticsearch" => EsPartitionInstanceType::M4LargeElasticsearch,
            "m4.xlarge.elasticsearch" => EsPartitionInstanceType::M4XlargeElasticsearch,
            "m5.12xlarge.elasticsearch" => EsPartitionInstanceType::M512xlargeElasticsearch,
            "m5.2xlarge.elasticsearch" => EsPartitionInstanceType::M52xlargeElasticsearch,
            "m5.4xlarge.elasticsearch" => EsPartitionInstanceType::M54xlargeElasticsearch,
            "m5.large.elasticsearch" => EsPartitionInstanceType::M5LargeElasticsearch,
            "m5.xlarge.elasticsearch" => EsPartitionInstanceType::M5XlargeElasticsearch,
            "r3.2xlarge.elasticsearch" => EsPartitionInstanceType::R32xlargeElasticsearch,
            "r3.4xlarge.elasticsearch" => EsPartitionInstanceType::R34xlargeElasticsearch,
            "r3.8xlarge.elasticsearch" => EsPartitionInstanceType::R38xlargeElasticsearch,
            "r3.large.elasticsearch" => EsPartitionInstanceType::R3LargeElasticsearch,
            "r3.xlarge.elasticsearch" => EsPartitionInstanceType::R3XlargeElasticsearch,
            "r4.16xlarge.elasticsearch" => EsPartitionInstanceType::R416xlargeElasticsearch,
            "r4.2xlarge.elasticsearch" => EsPartitionInstanceType::R42xlargeElasticsearch,
            "r4.4xlarge.elasticsearch" => EsPartitionInstanceType::R44xlargeElasticsearch,
            "r4.8xlarge.elasticsearch" => EsPartitionInstanceType::R48xlargeElasticsearch,
            "r4.large.elasticsearch" => EsPartitionInstanceType::R4LargeElasticsearch,
            "r4.xlarge.elasticsearch" => EsPartitionInstanceType::R4XlargeElasticsearch,
            "r5.12xlarge.elasticsearch" => EsPartitionInstanceType::R512xlargeElasticsearch,
            "r5.2xlarge.elasticsearch" => EsPartitionInstanceType::R52xlargeElasticsearch,
            "r5.4xlarge.elasticsearch" => EsPartitionInstanceType::R54xlargeElasticsearch,
            "r5.large.elasticsearch" => EsPartitionInstanceType::R5LargeElasticsearch,
            "r5.xlarge.elasticsearch" => EsPartitionInstanceType::R5XlargeElasticsearch,
            "t2.medium.elasticsearch" => EsPartitionInstanceType::T2MediumElasticsearch,
            "t2.micro.elasticsearch" => EsPartitionInstanceType::T2MicroElasticsearch,
            "t2.small.elasticsearch" => EsPartitionInstanceType::T2SmallElasticsearch,
            "ultrawarm1.large.elasticsearch" => EsPartitionInstanceType::Ultrawarm1LargeElasticsearch,
            "ultrawarm1.medium.elasticsearch" => EsPartitionInstanceType::Ultrawarm1MediumElasticsearch,
            other => EsPartitionInstanceType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for EsPartitionInstanceType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(EsPartitionInstanceType::from(s))
    }
}
impl EsPartitionInstanceType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            EsPartitionInstanceType::C42xlargeElasticsearch => "c4.2xlarge.elasticsearch",
            EsPartitionInstanceType::C44xlargeElasticsearch => "c4.4xlarge.elasticsearch",
            EsPartitionInstanceType::C48xlargeElasticsearch => "c4.8xlarge.elasticsearch",
            EsPartitionInstanceType::C4LargeElasticsearch => "c4.large.elasticsearch",
            EsPartitionInstanceType::C4XlargeElasticsearch => "c4.xlarge.elasticsearch",
            EsPartitionInstanceType::C518xlargeElasticsearch => "c5.18xlarge.elasticsearch",
            EsPartitionInstanceType::C52xlargeElasticsearch => "c5.2xlarge.elasticsearch",
            EsPartitionInstanceType::C54xlargeElasticsearch => "c5.4xlarge.elasticsearch",
            EsPartitionInstanceType::C59xlargeElasticsearch => "c5.9xlarge.elasticsearch",
            EsPartitionInstanceType::C5LargeElasticsearch => "c5.large.elasticsearch",
            EsPartitionInstanceType::C5XlargeElasticsearch => "c5.xlarge.elasticsearch",
            EsPartitionInstanceType::D22xlargeElasticsearch => "d2.2xlarge.elasticsearch",
            EsPartitionInstanceType::D24xlargeElasticsearch => "d2.4xlarge.elasticsearch",
            EsPartitionInstanceType::D28xlargeElasticsearch => "d2.8xlarge.elasticsearch",
            EsPartitionInstanceType::D2XlargeElasticsearch => "d2.xlarge.elasticsearch",
            EsPartitionInstanceType::I22xlargeElasticsearch => "i2.2xlarge.elasticsearch",
            EsPartitionInstanceType::I2XlargeElasticsearch => "i2.xlarge.elasticsearch",
            EsPartitionInstanceType::I316xlargeElasticsearch => "i3.16xlarge.elasticsearch",
            EsPartitionInstanceType::I32xlargeElasticsearch => "i3.2xlarge.elasticsearch",
            EsPartitionInstanceType::I34xlargeElasticsearch => "i3.4xlarge.elasticsearch",
            EsPartitionInstanceType::I38xlargeElasticsearch => "i3.8xlarge.elasticsearch",
            EsPartitionInstanceType::I3LargeElasticsearch => "i3.large.elasticsearch",
            EsPartitionInstanceType::I3XlargeElasticsearch => "i3.xlarge.elasticsearch",
            EsPartitionInstanceType::M32xlargeElasticsearch => "m3.2xlarge.elasticsearch",
            EsPartitionInstanceType::M3LargeElasticsearch => "m3.large.elasticsearch",
            EsPartitionInstanceType::M3MediumElasticsearch => "m3.medium.elasticsearch",
            EsPartitionInstanceType::M3XlargeElasticsearch => "m3.xlarge.elasticsearch",
            EsPartitionInstanceType::M410xlargeElasticsearch => "m4.10xlarge.elasticsearch",
            EsPartitionInstanceType::M42xlargeElasticsearch => "m4.2xlarge.elasticsearch",
            EsPartitionInstanceType::M44xlargeElasticsearch => "m4.4xlarge.elasticsearch",
            EsPartitionInstanceType::M4LargeElasticsearch => "m4.large.elasticsearch",
            EsPartitionInstanceType::M4XlargeElasticsearch => "m4.xlarge.elasticsearch",
            EsPartitionInstanceType::M512xlargeElasticsearch => "m5.12xlarge.elasticsearch",
            EsPartitionInstanceType::M52xlargeElasticsearch => "m5.2xlarge.elasticsearch",
            EsPartitionInstanceType::M54xlargeElasticsearch => "m5.4xlarge.elasticsearch",
            EsPartitionInstanceType::M5LargeElasticsearch => "m5.large.elasticsearch",
            EsPartitionInstanceType::M5XlargeElasticsearch => "m5.xlarge.elasticsearch",
            EsPartitionInstanceType::R32xlargeElasticsearch => "r3.2xlarge.elasticsearch",
            EsPartitionInstanceType::R34xlargeElasticsearch => "r3.4xlarge.elasticsearch",
            EsPartitionInstanceType::R38xlargeElasticsearch => "r3.8xlarge.elasticsearch",
            EsPartitionInstanceType::R3LargeElasticsearch => "r3.large.elasticsearch",
            EsPartitionInstanceType::R3XlargeElasticsearch => "r3.xlarge.elasticsearch",
            EsPartitionInstanceType::R416xlargeElasticsearch => "r4.16xlarge.elasticsearch",
            EsPartitionInstanceType::R42xlargeElasticsearch => "r4.2xlarge.elasticsearch",
            EsPartitionInstanceType::R44xlargeElasticsearch => "r4.4xlarge.elasticsearch",
            EsPartitionInstanceType::R48xlargeElasticsearch => "r4.8xlarge.elasticsearch",
            EsPartitionInstanceType::R4LargeElasticsearch => "r4.large.elasticsearch",
            EsPartitionInstanceType::R4XlargeElasticsearch => "r4.xlarge.elasticsearch",
            EsPartitionInstanceType::R512xlargeElasticsearch => "r5.12xlarge.elasticsearch",
            EsPartitionInstanceType::R52xlargeElasticsearch => "r5.2xlarge.elasticsearch",
            EsPartitionInstanceType::R54xlargeElasticsearch => "r5.4xlarge.elasticsearch",
            EsPartitionInstanceType::R5LargeElasticsearch => "r5.large.elasticsearch",
            EsPartitionInstanceType::R5XlargeElasticsearch => "r5.xlarge.elasticsearch",
            EsPartitionInstanceType::T2MediumElasticsearch => "t2.medium.elasticsearch",
            EsPartitionInstanceType::T2MicroElasticsearch => "t2.micro.elasticsearch",
            EsPartitionInstanceType::T2SmallElasticsearch => "t2.small.elasticsearch",
            EsPartitionInstanceType::Ultrawarm1LargeElasticsearch => "ultrawarm1.large.elasticsearch",
            EsPartitionInstanceType::Ultrawarm1MediumElasticsearch => "ultrawarm1.medium.elasticsearch",
            EsPartitionInstanceType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "c4.2xlarge.elasticsearch",
            "c4.4xlarge.elasticsearch",
            "c4.8xlarge.elasticsearch",
            "c4.large.elasticsearch",
            "c4.xlarge.elasticsearch",
            "c5.18xlarge.elasticsearch",
            "c5.2xlarge.elasticsearch",
            "c5.4xlarge.elasticsearch",
            "c5.9xlarge.elasticsearch",
            "c5.large.elasticsearch",
            "c5.xlarge.elasticsearch",
            "d2.2xlarge.elasticsearch",
            "d2.4xlarge.elasticsearch",
            "d2.8xlarge.elasticsearch",
            "d2.xlarge.elasticsearch",
            "i2.2xlarge.elasticsearch",
            "i2.xlarge.elasticsearch",
            "i3.16xlarge.elasticsearch",
            "i3.2xlarge.elasticsearch",
            "i3.4xlarge.elasticsearch",
            "i3.8xlarge.elasticsearch",
            "i3.large.elasticsearch",
            "i3.xlarge.elasticsearch",
            "m3.2xlarge.elasticsearch",
            "m3.large.elasticsearch",
            "m3.medium.elasticsearch",
            "m3.xlarge.elasticsearch",
            "m4.10xlarge.elasticsearch",
            "m4.2xlarge.elasticsearch",
            "m4.4xlarge.elasticsearch",
            "m4.large.elasticsearch",
            "m4.xlarge.elasticsearch",
            "m5.12xlarge.elasticsearch",
            "m5.2xlarge.elasticsearch",
            "m5.4xlarge.elasticsearch",
            "m5.large.elasticsearch",
            "m5.xlarge.elasticsearch",
            "r3.2xlarge.elasticsearch",
            "r3.4xlarge.elasticsearch",
            "r3.8xlarge.elasticsearch",
            "r3.large.elasticsearch",
            "r3.xlarge.elasticsearch",
            "r4.16xlarge.elasticsearch",
            "r4.2xlarge.elasticsearch",
            "r4.4xlarge.elasticsearch",
            "r4.8xlarge.elasticsearch",
            "r4.large.elasticsearch",
            "r4.xlarge.elasticsearch",
            "r5.12xlarge.elasticsearch",
            "r5.2xlarge.elasticsearch",
            "r5.4xlarge.elasticsearch",
            "r5.large.elasticsearch",
            "r5.xlarge.elasticsearch",
            "t2.medium.elasticsearch",
            "t2.micro.elasticsearch",
            "t2.small.elasticsearch",
            "ultrawarm1.large.elasticsearch",
            "ultrawarm1.medium.elasticsearch",
        ]
    }
}
impl ::std::convert::AsRef<str> for EsPartitionInstanceType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl EsPartitionInstanceType {
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
impl ::std::fmt::Display for EsPartitionInstanceType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            EsPartitionInstanceType::C42xlargeElasticsearch => write!(f, "c4.2xlarge.elasticsearch"),
            EsPartitionInstanceType::C44xlargeElasticsearch => write!(f, "c4.4xlarge.elasticsearch"),
            EsPartitionInstanceType::C48xlargeElasticsearch => write!(f, "c4.8xlarge.elasticsearch"),
            EsPartitionInstanceType::C4LargeElasticsearch => write!(f, "c4.large.elasticsearch"),
            EsPartitionInstanceType::C4XlargeElasticsearch => write!(f, "c4.xlarge.elasticsearch"),
            EsPartitionInstanceType::C518xlargeElasticsearch => write!(f, "c5.18xlarge.elasticsearch"),
            EsPartitionInstanceType::C52xlargeElasticsearch => write!(f, "c5.2xlarge.elasticsearch"),
            EsPartitionInstanceType::C54xlargeElasticsearch => write!(f, "c5.4xlarge.elasticsearch"),
            EsPartitionInstanceType::C59xlargeElasticsearch => write!(f, "c5.9xlarge.elasticsearch"),
            EsPartitionInstanceType::C5LargeElasticsearch => write!(f, "c5.large.elasticsearch"),
            EsPartitionInstanceType::C5XlargeElasticsearch => write!(f, "c5.xlarge.elasticsearch"),
            EsPartitionInstanceType::D22xlargeElasticsearch => write!(f, "d2.2xlarge.elasticsearch"),
            EsPartitionInstanceType::D24xlargeElasticsearch => write!(f, "d2.4xlarge.elasticsearch"),
            EsPartitionInstanceType::D28xlargeElasticsearch => write!(f, "d2.8xlarge.elasticsearch"),
            EsPartitionInstanceType::D2XlargeElasticsearch => write!(f, "d2.xlarge.elasticsearch"),
            EsPartitionInstanceType::I22xlargeElasticsearch => write!(f, "i2.2xlarge.elasticsearch"),
            EsPartitionInstanceType::I2XlargeElasticsearch => write!(f, "i2.xlarge.elasticsearch"),
            EsPartitionInstanceType::I316xlargeElasticsearch => write!(f, "i3.16xlarge.elasticsearch"),
            EsPartitionInstanceType::I32xlargeElasticsearch => write!(f, "i3.2xlarge.elasticsearch"),
            EsPartitionInstanceType::I34xlargeElasticsearch => write!(f, "i3.4xlarge.elasticsearch"),
            EsPartitionInstanceType::I38xlargeElasticsearch => write!(f, "i3.8xlarge.elasticsearch"),
            EsPartitionInstanceType::I3LargeElasticsearch => write!(f, "i3.large.elasticsearch"),
            EsPartitionInstanceType::I3XlargeElasticsearch => write!(f, "i3.xlarge.elasticsearch"),
            EsPartitionInstanceType::M32xlargeElasticsearch => write!(f, "m3.2xlarge.elasticsearch"),
            EsPartitionInstanceType::M3LargeElasticsearch => write!(f, "m3.large.elasticsearch"),
            EsPartitionInstanceType::M3MediumElasticsearch => write!(f, "m3.medium.elasticsearch"),
            EsPartitionInstanceType::M3XlargeElasticsearch => write!(f, "m3.xlarge.elasticsearch"),
            EsPartitionInstanceType::M410xlargeElasticsearch => write!(f, "m4.10xlarge.elasticsearch"),
            EsPartitionInstanceType::M42xlargeElasticsearch => write!(f, "m4.2xlarge.elasticsearch"),
            EsPartitionInstanceType::M44xlargeElasticsearch => write!(f, "m4.4xlarge.elasticsearch"),
            EsPartitionInstanceType::M4LargeElasticsearch => write!(f, "m4.large.elasticsearch"),
            EsPartitionInstanceType::M4XlargeElasticsearch => write!(f, "m4.xlarge.elasticsearch"),
            EsPartitionInstanceType::M512xlargeElasticsearch => write!(f, "m5.12xlarge.elasticsearch"),
            EsPartitionInstanceType::M52xlargeElasticsearch => write!(f, "m5.2xlarge.elasticsearch"),
            EsPartitionInstanceType::M54xlargeElasticsearch => write!(f, "m5.4xlarge.elasticsearch"),
            EsPartitionInstanceType::M5LargeElasticsearch => write!(f, "m5.large.elasticsearch"),
            EsPartitionInstanceType::M5XlargeElasticsearch => write!(f, "m5.xlarge.elasticsearch"),
            EsPartitionInstanceType::R32xlargeElasticsearch => write!(f, "r3.2xlarge.elasticsearch"),
            EsPartitionInstanceType::R34xlargeElasticsearch => write!(f, "r3.4xlarge.elasticsearch"),
            EsPartitionInstanceType::R38xlargeElasticsearch => write!(f, "r3.8xlarge.elasticsearch"),
            EsPartitionInstanceType::R3LargeElasticsearch => write!(f, "r3.large.elasticsearch"),
            EsPartitionInstanceType::R3XlargeElasticsearch => write!(f, "r3.xlarge.elasticsearch"),
            EsPartitionInstanceType::R416xlargeElasticsearch => write!(f, "r4.16xlarge.elasticsearch"),
            EsPartitionInstanceType::R42xlargeElasticsearch => write!(f, "r4.2xlarge.elasticsearch"),
            EsPartitionInstanceType::R44xlargeElasticsearch => write!(f, "r4.4xlarge.elasticsearch"),
            EsPartitionInstanceType::R48xlargeElasticsearch => write!(f, "r4.8xlarge.elasticsearch"),
            EsPartitionInstanceType::R4LargeElasticsearch => write!(f, "r4.large.elasticsearch"),
            EsPartitionInstanceType::R4XlargeElasticsearch => write!(f, "r4.xlarge.elasticsearch"),
            EsPartitionInstanceType::R512xlargeElasticsearch => write!(f, "r5.12xlarge.elasticsearch"),
            EsPartitionInstanceType::R52xlargeElasticsearch => write!(f, "r5.2xlarge.elasticsearch"),
            EsPartitionInstanceType::R54xlargeElasticsearch => write!(f, "r5.4xlarge.elasticsearch"),
            EsPartitionInstanceType::R5LargeElasticsearch => write!(f, "r5.large.elasticsearch"),
            EsPartitionInstanceType::R5XlargeElasticsearch => write!(f, "r5.xlarge.elasticsearch"),
            EsPartitionInstanceType::T2MediumElasticsearch => write!(f, "t2.medium.elasticsearch"),
            EsPartitionInstanceType::T2MicroElasticsearch => write!(f, "t2.micro.elasticsearch"),
            EsPartitionInstanceType::T2SmallElasticsearch => write!(f, "t2.small.elasticsearch"),
            EsPartitionInstanceType::Ultrawarm1LargeElasticsearch => write!(f, "ultrawarm1.large.elasticsearch"),
            EsPartitionInstanceType::Ultrawarm1MediumElasticsearch => write!(f, "ultrawarm1.medium.elasticsearch"),
            EsPartitionInstanceType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
