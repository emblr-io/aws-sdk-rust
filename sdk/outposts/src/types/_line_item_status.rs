// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `LineItemStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let lineitemstatus = unimplemented!();
/// match lineitemstatus {
///     LineItemStatus::Building => { /* ... */ },
///     LineItemStatus::Cancelled => { /* ... */ },
///     LineItemStatus::Delivered => { /* ... */ },
///     LineItemStatus::Error => { /* ... */ },
///     LineItemStatus::Installed => { /* ... */ },
///     LineItemStatus::Installing => { /* ... */ },
///     LineItemStatus::Preparing => { /* ... */ },
///     LineItemStatus::Replaced => { /* ... */ },
///     LineItemStatus::Shipped => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `lineitemstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `LineItemStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `LineItemStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `LineItemStatus::NewFeature` is defined.
/// Specifically, when `lineitemstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `LineItemStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum LineItemStatus {
    #[allow(missing_docs)] // documentation missing in model
    Building,
    #[allow(missing_docs)] // documentation missing in model
    Cancelled,
    #[allow(missing_docs)] // documentation missing in model
    Delivered,
    #[allow(missing_docs)] // documentation missing in model
    Error,
    #[allow(missing_docs)] // documentation missing in model
    Installed,
    #[allow(missing_docs)] // documentation missing in model
    Installing,
    #[allow(missing_docs)] // documentation missing in model
    Preparing,
    #[allow(missing_docs)] // documentation missing in model
    Replaced,
    #[allow(missing_docs)] // documentation missing in model
    Shipped,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for LineItemStatus {
    fn from(s: &str) -> Self {
        match s {
            "BUILDING" => LineItemStatus::Building,
            "CANCELLED" => LineItemStatus::Cancelled,
            "DELIVERED" => LineItemStatus::Delivered,
            "ERROR" => LineItemStatus::Error,
            "INSTALLED" => LineItemStatus::Installed,
            "INSTALLING" => LineItemStatus::Installing,
            "PREPARING" => LineItemStatus::Preparing,
            "REPLACED" => LineItemStatus::Replaced,
            "SHIPPED" => LineItemStatus::Shipped,
            other => LineItemStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for LineItemStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(LineItemStatus::from(s))
    }
}
impl LineItemStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            LineItemStatus::Building => "BUILDING",
            LineItemStatus::Cancelled => "CANCELLED",
            LineItemStatus::Delivered => "DELIVERED",
            LineItemStatus::Error => "ERROR",
            LineItemStatus::Installed => "INSTALLED",
            LineItemStatus::Installing => "INSTALLING",
            LineItemStatus::Preparing => "PREPARING",
            LineItemStatus::Replaced => "REPLACED",
            LineItemStatus::Shipped => "SHIPPED",
            LineItemStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "BUILDING",
            "CANCELLED",
            "DELIVERED",
            "ERROR",
            "INSTALLED",
            "INSTALLING",
            "PREPARING",
            "REPLACED",
            "SHIPPED",
        ]
    }
}
impl ::std::convert::AsRef<str> for LineItemStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl LineItemStatus {
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
impl ::std::fmt::Display for LineItemStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            LineItemStatus::Building => write!(f, "BUILDING"),
            LineItemStatus::Cancelled => write!(f, "CANCELLED"),
            LineItemStatus::Delivered => write!(f, "DELIVERED"),
            LineItemStatus::Error => write!(f, "ERROR"),
            LineItemStatus::Installed => write!(f, "INSTALLED"),
            LineItemStatus::Installing => write!(f, "INSTALLING"),
            LineItemStatus::Preparing => write!(f, "PREPARING"),
            LineItemStatus::Replaced => write!(f, "REPLACED"),
            LineItemStatus::Shipped => write!(f, "SHIPPED"),
            LineItemStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
