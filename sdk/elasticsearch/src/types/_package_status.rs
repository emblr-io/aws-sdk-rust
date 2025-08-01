// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `PackageStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let packagestatus = unimplemented!();
/// match packagestatus {
///     PackageStatus::Available => { /* ... */ },
///     PackageStatus::Copying => { /* ... */ },
///     PackageStatus::CopyFailed => { /* ... */ },
///     PackageStatus::Deleted => { /* ... */ },
///     PackageStatus::DeleteFailed => { /* ... */ },
///     PackageStatus::Deleting => { /* ... */ },
///     PackageStatus::Validating => { /* ... */ },
///     PackageStatus::ValidationFailed => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `packagestatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `PackageStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `PackageStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `PackageStatus::NewFeature` is defined.
/// Specifically, when `packagestatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `PackageStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum PackageStatus {
    #[allow(missing_docs)] // documentation missing in model
    Available,
    #[allow(missing_docs)] // documentation missing in model
    Copying,
    #[allow(missing_docs)] // documentation missing in model
    CopyFailed,
    #[allow(missing_docs)] // documentation missing in model
    Deleted,
    #[allow(missing_docs)] // documentation missing in model
    DeleteFailed,
    #[allow(missing_docs)] // documentation missing in model
    Deleting,
    #[allow(missing_docs)] // documentation missing in model
    Validating,
    #[allow(missing_docs)] // documentation missing in model
    ValidationFailed,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for PackageStatus {
    fn from(s: &str) -> Self {
        match s {
            "AVAILABLE" => PackageStatus::Available,
            "COPYING" => PackageStatus::Copying,
            "COPY_FAILED" => PackageStatus::CopyFailed,
            "DELETED" => PackageStatus::Deleted,
            "DELETE_FAILED" => PackageStatus::DeleteFailed,
            "DELETING" => PackageStatus::Deleting,
            "VALIDATING" => PackageStatus::Validating,
            "VALIDATION_FAILED" => PackageStatus::ValidationFailed,
            other => PackageStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for PackageStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(PackageStatus::from(s))
    }
}
impl PackageStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            PackageStatus::Available => "AVAILABLE",
            PackageStatus::Copying => "COPYING",
            PackageStatus::CopyFailed => "COPY_FAILED",
            PackageStatus::Deleted => "DELETED",
            PackageStatus::DeleteFailed => "DELETE_FAILED",
            PackageStatus::Deleting => "DELETING",
            PackageStatus::Validating => "VALIDATING",
            PackageStatus::ValidationFailed => "VALIDATION_FAILED",
            PackageStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AVAILABLE",
            "COPYING",
            "COPY_FAILED",
            "DELETED",
            "DELETE_FAILED",
            "DELETING",
            "VALIDATING",
            "VALIDATION_FAILED",
        ]
    }
}
impl ::std::convert::AsRef<str> for PackageStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl PackageStatus {
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
impl ::std::fmt::Display for PackageStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PackageStatus::Available => write!(f, "AVAILABLE"),
            PackageStatus::Copying => write!(f, "COPYING"),
            PackageStatus::CopyFailed => write!(f, "COPY_FAILED"),
            PackageStatus::Deleted => write!(f, "DELETED"),
            PackageStatus::DeleteFailed => write!(f, "DELETE_FAILED"),
            PackageStatus::Deleting => write!(f, "DELETING"),
            PackageStatus::Validating => write!(f, "VALIDATING"),
            PackageStatus::ValidationFailed => write!(f, "VALIDATION_FAILED"),
            PackageStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
