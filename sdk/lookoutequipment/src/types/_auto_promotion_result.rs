// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AutoPromotionResult`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let autopromotionresult = unimplemented!();
/// match autopromotionresult {
///     AutoPromotionResult::ModelNotPromoted => { /* ... */ },
///     AutoPromotionResult::ModelPromoted => { /* ... */ },
///     AutoPromotionResult::RetrainingCancelled => { /* ... */ },
///     AutoPromotionResult::RetrainingCustomerError => { /* ... */ },
///     AutoPromotionResult::RetrainingInternalError => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `autopromotionresult` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AutoPromotionResult::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AutoPromotionResult::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AutoPromotionResult::NewFeature` is defined.
/// Specifically, when `autopromotionresult` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AutoPromotionResult::NewFeature` also yielding `"NewFeature"`.
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
pub enum AutoPromotionResult {
    #[allow(missing_docs)] // documentation missing in model
    ModelNotPromoted,
    #[allow(missing_docs)] // documentation missing in model
    ModelPromoted,
    #[allow(missing_docs)] // documentation missing in model
    RetrainingCancelled,
    #[allow(missing_docs)] // documentation missing in model
    RetrainingCustomerError,
    #[allow(missing_docs)] // documentation missing in model
    RetrainingInternalError,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AutoPromotionResult {
    fn from(s: &str) -> Self {
        match s {
            "MODEL_NOT_PROMOTED" => AutoPromotionResult::ModelNotPromoted,
            "MODEL_PROMOTED" => AutoPromotionResult::ModelPromoted,
            "RETRAINING_CANCELLED" => AutoPromotionResult::RetrainingCancelled,
            "RETRAINING_CUSTOMER_ERROR" => AutoPromotionResult::RetrainingCustomerError,
            "RETRAINING_INTERNAL_ERROR" => AutoPromotionResult::RetrainingInternalError,
            other => AutoPromotionResult::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AutoPromotionResult {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AutoPromotionResult::from(s))
    }
}
impl AutoPromotionResult {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AutoPromotionResult::ModelNotPromoted => "MODEL_NOT_PROMOTED",
            AutoPromotionResult::ModelPromoted => "MODEL_PROMOTED",
            AutoPromotionResult::RetrainingCancelled => "RETRAINING_CANCELLED",
            AutoPromotionResult::RetrainingCustomerError => "RETRAINING_CUSTOMER_ERROR",
            AutoPromotionResult::RetrainingInternalError => "RETRAINING_INTERNAL_ERROR",
            AutoPromotionResult::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "MODEL_NOT_PROMOTED",
            "MODEL_PROMOTED",
            "RETRAINING_CANCELLED",
            "RETRAINING_CUSTOMER_ERROR",
            "RETRAINING_INTERNAL_ERROR",
        ]
    }
}
impl ::std::convert::AsRef<str> for AutoPromotionResult {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AutoPromotionResult {
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
impl ::std::fmt::Display for AutoPromotionResult {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AutoPromotionResult::ModelNotPromoted => write!(f, "MODEL_NOT_PROMOTED"),
            AutoPromotionResult::ModelPromoted => write!(f, "MODEL_PROMOTED"),
            AutoPromotionResult::RetrainingCancelled => write!(f, "RETRAINING_CANCELLED"),
            AutoPromotionResult::RetrainingCustomerError => write!(f, "RETRAINING_CUSTOMER_ERROR"),
            AutoPromotionResult::RetrainingInternalError => write!(f, "RETRAINING_INTERNAL_ERROR"),
            AutoPromotionResult::Unknown(value) => write!(f, "{}", value),
        }
    }
}
