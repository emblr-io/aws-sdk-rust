// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `TaxRegistrationType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let taxregistrationtype = unimplemented!();
/// match taxregistrationtype {
///     TaxRegistrationType::Cnpj => { /* ... */ },
///     TaxRegistrationType::Cpf => { /* ... */ },
///     TaxRegistrationType::Gst => { /* ... */ },
///     TaxRegistrationType::Nric => { /* ... */ },
///     TaxRegistrationType::Sst => { /* ... */ },
///     TaxRegistrationType::Tin => { /* ... */ },
///     TaxRegistrationType::Vat => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `taxregistrationtype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `TaxRegistrationType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `TaxRegistrationType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `TaxRegistrationType::NewFeature` is defined.
/// Specifically, when `taxregistrationtype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `TaxRegistrationType::NewFeature` also yielding `"NewFeature"`.
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
pub enum TaxRegistrationType {
    #[allow(missing_docs)] // documentation missing in model
    Cnpj,
    #[allow(missing_docs)] // documentation missing in model
    Cpf,
    #[allow(missing_docs)] // documentation missing in model
    Gst,
    #[allow(missing_docs)] // documentation missing in model
    Nric,
    #[allow(missing_docs)] // documentation missing in model
    Sst,
    #[allow(missing_docs)] // documentation missing in model
    Tin,
    #[allow(missing_docs)] // documentation missing in model
    Vat,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for TaxRegistrationType {
    fn from(s: &str) -> Self {
        match s {
            "CNPJ" => TaxRegistrationType::Cnpj,
            "CPF" => TaxRegistrationType::Cpf,
            "GST" => TaxRegistrationType::Gst,
            "NRIC" => TaxRegistrationType::Nric,
            "SST" => TaxRegistrationType::Sst,
            "TIN" => TaxRegistrationType::Tin,
            "VAT" => TaxRegistrationType::Vat,
            other => TaxRegistrationType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for TaxRegistrationType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(TaxRegistrationType::from(s))
    }
}
impl TaxRegistrationType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            TaxRegistrationType::Cnpj => "CNPJ",
            TaxRegistrationType::Cpf => "CPF",
            TaxRegistrationType::Gst => "GST",
            TaxRegistrationType::Nric => "NRIC",
            TaxRegistrationType::Sst => "SST",
            TaxRegistrationType::Tin => "TIN",
            TaxRegistrationType::Vat => "VAT",
            TaxRegistrationType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["CNPJ", "CPF", "GST", "NRIC", "SST", "TIN", "VAT"]
    }
}
impl ::std::convert::AsRef<str> for TaxRegistrationType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl TaxRegistrationType {
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
impl ::std::fmt::Display for TaxRegistrationType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            TaxRegistrationType::Cnpj => write!(f, "CNPJ"),
            TaxRegistrationType::Cpf => write!(f, "CPF"),
            TaxRegistrationType::Gst => write!(f, "GST"),
            TaxRegistrationType::Nric => write!(f, "NRIC"),
            TaxRegistrationType::Sst => write!(f, "SST"),
            TaxRegistrationType::Tin => write!(f, "TIN"),
            TaxRegistrationType::Vat => write!(f, "VAT"),
            TaxRegistrationType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
