// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `TrustState`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let truststate = unimplemented!();
/// match truststate {
///     TrustState::Created => { /* ... */ },
///     TrustState::Creating => { /* ... */ },
///     TrustState::Deleted => { /* ... */ },
///     TrustState::Deleting => { /* ... */ },
///     TrustState::Failed => { /* ... */ },
///     TrustState::UpdateFailed => { /* ... */ },
///     TrustState::Updated => { /* ... */ },
///     TrustState::Updating => { /* ... */ },
///     TrustState::Verified => { /* ... */ },
///     TrustState::VerifyFailed => { /* ... */ },
///     TrustState::Verifying => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `truststate` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `TrustState::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `TrustState::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `TrustState::NewFeature` is defined.
/// Specifically, when `truststate` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `TrustState::NewFeature` also yielding `"NewFeature"`.
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
pub enum TrustState {
    #[allow(missing_docs)] // documentation missing in model
    Created,
    #[allow(missing_docs)] // documentation missing in model
    Creating,
    #[allow(missing_docs)] // documentation missing in model
    Deleted,
    #[allow(missing_docs)] // documentation missing in model
    Deleting,
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    #[allow(missing_docs)] // documentation missing in model
    UpdateFailed,
    #[allow(missing_docs)] // documentation missing in model
    Updated,
    #[allow(missing_docs)] // documentation missing in model
    Updating,
    #[allow(missing_docs)] // documentation missing in model
    Verified,
    #[allow(missing_docs)] // documentation missing in model
    VerifyFailed,
    #[allow(missing_docs)] // documentation missing in model
    Verifying,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for TrustState {
    fn from(s: &str) -> Self {
        match s {
            "Created" => TrustState::Created,
            "Creating" => TrustState::Creating,
            "Deleted" => TrustState::Deleted,
            "Deleting" => TrustState::Deleting,
            "Failed" => TrustState::Failed,
            "UpdateFailed" => TrustState::UpdateFailed,
            "Updated" => TrustState::Updated,
            "Updating" => TrustState::Updating,
            "Verified" => TrustState::Verified,
            "VerifyFailed" => TrustState::VerifyFailed,
            "Verifying" => TrustState::Verifying,
            other => TrustState::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for TrustState {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(TrustState::from(s))
    }
}
impl TrustState {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            TrustState::Created => "Created",
            TrustState::Creating => "Creating",
            TrustState::Deleted => "Deleted",
            TrustState::Deleting => "Deleting",
            TrustState::Failed => "Failed",
            TrustState::UpdateFailed => "UpdateFailed",
            TrustState::Updated => "Updated",
            TrustState::Updating => "Updating",
            TrustState::Verified => "Verified",
            TrustState::VerifyFailed => "VerifyFailed",
            TrustState::Verifying => "Verifying",
            TrustState::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "Created",
            "Creating",
            "Deleted",
            "Deleting",
            "Failed",
            "UpdateFailed",
            "Updated",
            "Updating",
            "Verified",
            "VerifyFailed",
            "Verifying",
        ]
    }
}
impl ::std::convert::AsRef<str> for TrustState {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl TrustState {
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
impl ::std::fmt::Display for TrustState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            TrustState::Created => write!(f, "Created"),
            TrustState::Creating => write!(f, "Creating"),
            TrustState::Deleted => write!(f, "Deleted"),
            TrustState::Deleting => write!(f, "Deleting"),
            TrustState::Failed => write!(f, "Failed"),
            TrustState::UpdateFailed => write!(f, "UpdateFailed"),
            TrustState::Updated => write!(f, "Updated"),
            TrustState::Updating => write!(f, "Updating"),
            TrustState::Verified => write!(f, "Verified"),
            TrustState::VerifyFailed => write!(f, "VerifyFailed"),
            TrustState::Verifying => write!(f, "Verifying"),
            TrustState::Unknown(value) => write!(f, "{}", value),
        }
    }
}
