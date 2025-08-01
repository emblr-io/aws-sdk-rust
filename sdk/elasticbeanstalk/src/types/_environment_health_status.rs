// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `EnvironmentHealthStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let environmenthealthstatus = unimplemented!();
/// match environmenthealthstatus {
///     EnvironmentHealthStatus::Degraded => { /* ... */ },
///     EnvironmentHealthStatus::Info => { /* ... */ },
///     EnvironmentHealthStatus::NoData => { /* ... */ },
///     EnvironmentHealthStatus::Ok => { /* ... */ },
///     EnvironmentHealthStatus::Pending => { /* ... */ },
///     EnvironmentHealthStatus::Severe => { /* ... */ },
///     EnvironmentHealthStatus::Suspended => { /* ... */ },
///     EnvironmentHealthStatus::UnknownValue => { /* ... */ },
///     EnvironmentHealthStatus::Warning => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `environmenthealthstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `EnvironmentHealthStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `EnvironmentHealthStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `EnvironmentHealthStatus::NewFeature` is defined.
/// Specifically, when `environmenthealthstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `EnvironmentHealthStatus::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
///
/// _Note: `EnvironmentHealthStatus::Unknown` has been renamed to `::UnknownValue`._
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum EnvironmentHealthStatus {
    #[allow(missing_docs)] // documentation missing in model
    Degraded,
    #[allow(missing_docs)] // documentation missing in model
    Info,
    #[allow(missing_docs)] // documentation missing in model
    NoData,
    #[allow(missing_docs)] // documentation missing in model
    Ok,
    #[allow(missing_docs)] // documentation missing in model
    Pending,
    #[allow(missing_docs)] // documentation missing in model
    Severe,
    #[allow(missing_docs)] // documentation missing in model
    Suspended,
    ///
    /// _Note: `::Unknown` has been renamed to `::UnknownValue`._
    UnknownValue,
    #[allow(missing_docs)] // documentation missing in model
    Warning,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for EnvironmentHealthStatus {
    fn from(s: &str) -> Self {
        match s {
            "Degraded" => EnvironmentHealthStatus::Degraded,
            "Info" => EnvironmentHealthStatus::Info,
            "NoData" => EnvironmentHealthStatus::NoData,
            "Ok" => EnvironmentHealthStatus::Ok,
            "Pending" => EnvironmentHealthStatus::Pending,
            "Severe" => EnvironmentHealthStatus::Severe,
            "Suspended" => EnvironmentHealthStatus::Suspended,
            "Unknown" => EnvironmentHealthStatus::UnknownValue,
            "Warning" => EnvironmentHealthStatus::Warning,
            other => EnvironmentHealthStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for EnvironmentHealthStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(EnvironmentHealthStatus::from(s))
    }
}
impl EnvironmentHealthStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            EnvironmentHealthStatus::Degraded => "Degraded",
            EnvironmentHealthStatus::Info => "Info",
            EnvironmentHealthStatus::NoData => "NoData",
            EnvironmentHealthStatus::Ok => "Ok",
            EnvironmentHealthStatus::Pending => "Pending",
            EnvironmentHealthStatus::Severe => "Severe",
            EnvironmentHealthStatus::Suspended => "Suspended",
            EnvironmentHealthStatus::UnknownValue => "Unknown",
            EnvironmentHealthStatus::Warning => "Warning",
            EnvironmentHealthStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["Degraded", "Info", "NoData", "Ok", "Pending", "Severe", "Suspended", "Unknown", "Warning"]
    }
}
impl ::std::convert::AsRef<str> for EnvironmentHealthStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl EnvironmentHealthStatus {
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
impl ::std::fmt::Display for EnvironmentHealthStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            EnvironmentHealthStatus::Degraded => write!(f, "Degraded"),
            EnvironmentHealthStatus::Info => write!(f, "Info"),
            EnvironmentHealthStatus::NoData => write!(f, "NoData"),
            EnvironmentHealthStatus::Ok => write!(f, "Ok"),
            EnvironmentHealthStatus::Pending => write!(f, "Pending"),
            EnvironmentHealthStatus::Severe => write!(f, "Severe"),
            EnvironmentHealthStatus::Suspended => write!(f, "Suspended"),
            EnvironmentHealthStatus::UnknownValue => write!(f, "Unknown"),
            EnvironmentHealthStatus::Warning => write!(f, "Warning"),
            EnvironmentHealthStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
