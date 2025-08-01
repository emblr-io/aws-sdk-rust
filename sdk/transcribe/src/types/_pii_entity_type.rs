// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `PiiEntityType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let piientitytype = unimplemented!();
/// match piientitytype {
///     PiiEntityType::Address => { /* ... */ },
///     PiiEntityType::All => { /* ... */ },
///     PiiEntityType::BankAccountNumber => { /* ... */ },
///     PiiEntityType::BankRouting => { /* ... */ },
///     PiiEntityType::CreditDebitCvv => { /* ... */ },
///     PiiEntityType::CreditDebitExpiry => { /* ... */ },
///     PiiEntityType::CreditDebitNumber => { /* ... */ },
///     PiiEntityType::Email => { /* ... */ },
///     PiiEntityType::Name => { /* ... */ },
///     PiiEntityType::Phone => { /* ... */ },
///     PiiEntityType::Pin => { /* ... */ },
///     PiiEntityType::Ssn => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `piientitytype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `PiiEntityType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `PiiEntityType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `PiiEntityType::NewFeature` is defined.
/// Specifically, when `piientitytype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `PiiEntityType::NewFeature` also yielding `"NewFeature"`.
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
pub enum PiiEntityType {
    #[allow(missing_docs)] // documentation missing in model
    Address,
    #[allow(missing_docs)] // documentation missing in model
    All,
    #[allow(missing_docs)] // documentation missing in model
    BankAccountNumber,
    #[allow(missing_docs)] // documentation missing in model
    BankRouting,
    #[allow(missing_docs)] // documentation missing in model
    CreditDebitCvv,
    #[allow(missing_docs)] // documentation missing in model
    CreditDebitExpiry,
    #[allow(missing_docs)] // documentation missing in model
    CreditDebitNumber,
    #[allow(missing_docs)] // documentation missing in model
    Email,
    #[allow(missing_docs)] // documentation missing in model
    Name,
    #[allow(missing_docs)] // documentation missing in model
    Phone,
    #[allow(missing_docs)] // documentation missing in model
    Pin,
    #[allow(missing_docs)] // documentation missing in model
    Ssn,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for PiiEntityType {
    fn from(s: &str) -> Self {
        match s {
            "ADDRESS" => PiiEntityType::Address,
            "ALL" => PiiEntityType::All,
            "BANK_ACCOUNT_NUMBER" => PiiEntityType::BankAccountNumber,
            "BANK_ROUTING" => PiiEntityType::BankRouting,
            "CREDIT_DEBIT_CVV" => PiiEntityType::CreditDebitCvv,
            "CREDIT_DEBIT_EXPIRY" => PiiEntityType::CreditDebitExpiry,
            "CREDIT_DEBIT_NUMBER" => PiiEntityType::CreditDebitNumber,
            "EMAIL" => PiiEntityType::Email,
            "NAME" => PiiEntityType::Name,
            "PHONE" => PiiEntityType::Phone,
            "PIN" => PiiEntityType::Pin,
            "SSN" => PiiEntityType::Ssn,
            other => PiiEntityType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for PiiEntityType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(PiiEntityType::from(s))
    }
}
impl PiiEntityType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            PiiEntityType::Address => "ADDRESS",
            PiiEntityType::All => "ALL",
            PiiEntityType::BankAccountNumber => "BANK_ACCOUNT_NUMBER",
            PiiEntityType::BankRouting => "BANK_ROUTING",
            PiiEntityType::CreditDebitCvv => "CREDIT_DEBIT_CVV",
            PiiEntityType::CreditDebitExpiry => "CREDIT_DEBIT_EXPIRY",
            PiiEntityType::CreditDebitNumber => "CREDIT_DEBIT_NUMBER",
            PiiEntityType::Email => "EMAIL",
            PiiEntityType::Name => "NAME",
            PiiEntityType::Phone => "PHONE",
            PiiEntityType::Pin => "PIN",
            PiiEntityType::Ssn => "SSN",
            PiiEntityType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ADDRESS",
            "ALL",
            "BANK_ACCOUNT_NUMBER",
            "BANK_ROUTING",
            "CREDIT_DEBIT_CVV",
            "CREDIT_DEBIT_EXPIRY",
            "CREDIT_DEBIT_NUMBER",
            "EMAIL",
            "NAME",
            "PHONE",
            "PIN",
            "SSN",
        ]
    }
}
impl ::std::convert::AsRef<str> for PiiEntityType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl PiiEntityType {
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
impl ::std::fmt::Display for PiiEntityType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PiiEntityType::Address => write!(f, "ADDRESS"),
            PiiEntityType::All => write!(f, "ALL"),
            PiiEntityType::BankAccountNumber => write!(f, "BANK_ACCOUNT_NUMBER"),
            PiiEntityType::BankRouting => write!(f, "BANK_ROUTING"),
            PiiEntityType::CreditDebitCvv => write!(f, "CREDIT_DEBIT_CVV"),
            PiiEntityType::CreditDebitExpiry => write!(f, "CREDIT_DEBIT_EXPIRY"),
            PiiEntityType::CreditDebitNumber => write!(f, "CREDIT_DEBIT_NUMBER"),
            PiiEntityType::Email => write!(f, "EMAIL"),
            PiiEntityType::Name => write!(f, "NAME"),
            PiiEntityType::Phone => write!(f, "PHONE"),
            PiiEntityType::Pin => write!(f, "PIN"),
            PiiEntityType::Ssn => write!(f, "SSN"),
            PiiEntityType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
