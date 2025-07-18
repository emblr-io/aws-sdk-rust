// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ImageStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let imagestatus = unimplemented!();
/// match imagestatus {
///     ImageStatus::Available => { /* ... */ },
///     ImageStatus::Building => { /* ... */ },
///     ImageStatus::Cancelled => { /* ... */ },
///     ImageStatus::Creating => { /* ... */ },
///     ImageStatus::Deleted => { /* ... */ },
///     ImageStatus::Deprecated => { /* ... */ },
///     ImageStatus::Disabled => { /* ... */ },
///     ImageStatus::Distributing => { /* ... */ },
///     ImageStatus::Failed => { /* ... */ },
///     ImageStatus::Integrating => { /* ... */ },
///     ImageStatus::Pending => { /* ... */ },
///     ImageStatus::Testing => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `imagestatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ImageStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ImageStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ImageStatus::NewFeature` is defined.
/// Specifically, when `imagestatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ImageStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum ImageStatus {
    #[allow(missing_docs)] // documentation missing in model
    Available,
    #[allow(missing_docs)] // documentation missing in model
    Building,
    #[allow(missing_docs)] // documentation missing in model
    Cancelled,
    #[allow(missing_docs)] // documentation missing in model
    Creating,
    #[allow(missing_docs)] // documentation missing in model
    Deleted,
    #[allow(missing_docs)] // documentation missing in model
    Deprecated,
    #[allow(missing_docs)] // documentation missing in model
    Disabled,
    #[allow(missing_docs)] // documentation missing in model
    Distributing,
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    #[allow(missing_docs)] // documentation missing in model
    Integrating,
    #[allow(missing_docs)] // documentation missing in model
    Pending,
    #[allow(missing_docs)] // documentation missing in model
    Testing,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ImageStatus {
    fn from(s: &str) -> Self {
        match s {
            "AVAILABLE" => ImageStatus::Available,
            "BUILDING" => ImageStatus::Building,
            "CANCELLED" => ImageStatus::Cancelled,
            "CREATING" => ImageStatus::Creating,
            "DELETED" => ImageStatus::Deleted,
            "DEPRECATED" => ImageStatus::Deprecated,
            "DISABLED" => ImageStatus::Disabled,
            "DISTRIBUTING" => ImageStatus::Distributing,
            "FAILED" => ImageStatus::Failed,
            "INTEGRATING" => ImageStatus::Integrating,
            "PENDING" => ImageStatus::Pending,
            "TESTING" => ImageStatus::Testing,
            other => ImageStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ImageStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ImageStatus::from(s))
    }
}
impl ImageStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ImageStatus::Available => "AVAILABLE",
            ImageStatus::Building => "BUILDING",
            ImageStatus::Cancelled => "CANCELLED",
            ImageStatus::Creating => "CREATING",
            ImageStatus::Deleted => "DELETED",
            ImageStatus::Deprecated => "DEPRECATED",
            ImageStatus::Disabled => "DISABLED",
            ImageStatus::Distributing => "DISTRIBUTING",
            ImageStatus::Failed => "FAILED",
            ImageStatus::Integrating => "INTEGRATING",
            ImageStatus::Pending => "PENDING",
            ImageStatus::Testing => "TESTING",
            ImageStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AVAILABLE",
            "BUILDING",
            "CANCELLED",
            "CREATING",
            "DELETED",
            "DEPRECATED",
            "DISABLED",
            "DISTRIBUTING",
            "FAILED",
            "INTEGRATING",
            "PENDING",
            "TESTING",
        ]
    }
}
impl ::std::convert::AsRef<str> for ImageStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ImageStatus {
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
impl ::std::fmt::Display for ImageStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ImageStatus::Available => write!(f, "AVAILABLE"),
            ImageStatus::Building => write!(f, "BUILDING"),
            ImageStatus::Cancelled => write!(f, "CANCELLED"),
            ImageStatus::Creating => write!(f, "CREATING"),
            ImageStatus::Deleted => write!(f, "DELETED"),
            ImageStatus::Deprecated => write!(f, "DEPRECATED"),
            ImageStatus::Disabled => write!(f, "DISABLED"),
            ImageStatus::Distributing => write!(f, "DISTRIBUTING"),
            ImageStatus::Failed => write!(f, "FAILED"),
            ImageStatus::Integrating => write!(f, "INTEGRATING"),
            ImageStatus::Pending => write!(f, "PENDING"),
            ImageStatus::Testing => write!(f, "TESTING"),
            ImageStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
