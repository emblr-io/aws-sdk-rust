// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `KxVolumeStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let kxvolumestatus = unimplemented!();
/// match kxvolumestatus {
///     KxVolumeStatus::Active => { /* ... */ },
///     KxVolumeStatus::CreateFailed => { /* ... */ },
///     KxVolumeStatus::Creating => { /* ... */ },
///     KxVolumeStatus::Deleted => { /* ... */ },
///     KxVolumeStatus::DeleteFailed => { /* ... */ },
///     KxVolumeStatus::Deleting => { /* ... */ },
///     KxVolumeStatus::Updated => { /* ... */ },
///     KxVolumeStatus::UpdateFailed => { /* ... */ },
///     KxVolumeStatus::Updating => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `kxvolumestatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `KxVolumeStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `KxVolumeStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `KxVolumeStatus::NewFeature` is defined.
/// Specifically, when `kxvolumestatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `KxVolumeStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum KxVolumeStatus {
    #[allow(missing_docs)] // documentation missing in model
    Active,
    #[allow(missing_docs)] // documentation missing in model
    CreateFailed,
    #[allow(missing_docs)] // documentation missing in model
    Creating,
    #[allow(missing_docs)] // documentation missing in model
    Deleted,
    #[allow(missing_docs)] // documentation missing in model
    DeleteFailed,
    #[allow(missing_docs)] // documentation missing in model
    Deleting,
    #[allow(missing_docs)] // documentation missing in model
    Updated,
    #[allow(missing_docs)] // documentation missing in model
    UpdateFailed,
    #[allow(missing_docs)] // documentation missing in model
    Updating,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for KxVolumeStatus {
    fn from(s: &str) -> Self {
        match s {
            "ACTIVE" => KxVolumeStatus::Active,
            "CREATE_FAILED" => KxVolumeStatus::CreateFailed,
            "CREATING" => KxVolumeStatus::Creating,
            "DELETED" => KxVolumeStatus::Deleted,
            "DELETE_FAILED" => KxVolumeStatus::DeleteFailed,
            "DELETING" => KxVolumeStatus::Deleting,
            "UPDATED" => KxVolumeStatus::Updated,
            "UPDATE_FAILED" => KxVolumeStatus::UpdateFailed,
            "UPDATING" => KxVolumeStatus::Updating,
            other => KxVolumeStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for KxVolumeStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(KxVolumeStatus::from(s))
    }
}
impl KxVolumeStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            KxVolumeStatus::Active => "ACTIVE",
            KxVolumeStatus::CreateFailed => "CREATE_FAILED",
            KxVolumeStatus::Creating => "CREATING",
            KxVolumeStatus::Deleted => "DELETED",
            KxVolumeStatus::DeleteFailed => "DELETE_FAILED",
            KxVolumeStatus::Deleting => "DELETING",
            KxVolumeStatus::Updated => "UPDATED",
            KxVolumeStatus::UpdateFailed => "UPDATE_FAILED",
            KxVolumeStatus::Updating => "UPDATING",
            KxVolumeStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACTIVE",
            "CREATE_FAILED",
            "CREATING",
            "DELETED",
            "DELETE_FAILED",
            "DELETING",
            "UPDATED",
            "UPDATE_FAILED",
            "UPDATING",
        ]
    }
}
impl ::std::convert::AsRef<str> for KxVolumeStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl KxVolumeStatus {
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
impl ::std::fmt::Display for KxVolumeStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            KxVolumeStatus::Active => write!(f, "ACTIVE"),
            KxVolumeStatus::CreateFailed => write!(f, "CREATE_FAILED"),
            KxVolumeStatus::Creating => write!(f, "CREATING"),
            KxVolumeStatus::Deleted => write!(f, "DELETED"),
            KxVolumeStatus::DeleteFailed => write!(f, "DELETE_FAILED"),
            KxVolumeStatus::Deleting => write!(f, "DELETING"),
            KxVolumeStatus::Updated => write!(f, "UPDATED"),
            KxVolumeStatus::UpdateFailed => write!(f, "UPDATE_FAILED"),
            KxVolumeStatus::Updating => write!(f, "UPDATING"),
            KxVolumeStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
