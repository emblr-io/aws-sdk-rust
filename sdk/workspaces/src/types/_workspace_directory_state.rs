// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `WorkspaceDirectoryState`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let workspacedirectorystate = unimplemented!();
/// match workspacedirectorystate {
///     WorkspaceDirectoryState::Deregistered => { /* ... */ },
///     WorkspaceDirectoryState::Deregistering => { /* ... */ },
///     WorkspaceDirectoryState::Error => { /* ... */ },
///     WorkspaceDirectoryState::Registered => { /* ... */ },
///     WorkspaceDirectoryState::Registering => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `workspacedirectorystate` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `WorkspaceDirectoryState::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `WorkspaceDirectoryState::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `WorkspaceDirectoryState::NewFeature` is defined.
/// Specifically, when `workspacedirectorystate` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `WorkspaceDirectoryState::NewFeature` also yielding `"NewFeature"`.
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
pub enum WorkspaceDirectoryState {
    #[allow(missing_docs)] // documentation missing in model
    Deregistered,
    #[allow(missing_docs)] // documentation missing in model
    Deregistering,
    #[allow(missing_docs)] // documentation missing in model
    Error,
    #[allow(missing_docs)] // documentation missing in model
    Registered,
    #[allow(missing_docs)] // documentation missing in model
    Registering,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for WorkspaceDirectoryState {
    fn from(s: &str) -> Self {
        match s {
            "DEREGISTERED" => WorkspaceDirectoryState::Deregistered,
            "DEREGISTERING" => WorkspaceDirectoryState::Deregistering,
            "ERROR" => WorkspaceDirectoryState::Error,
            "REGISTERED" => WorkspaceDirectoryState::Registered,
            "REGISTERING" => WorkspaceDirectoryState::Registering,
            other => WorkspaceDirectoryState::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for WorkspaceDirectoryState {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(WorkspaceDirectoryState::from(s))
    }
}
impl WorkspaceDirectoryState {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            WorkspaceDirectoryState::Deregistered => "DEREGISTERED",
            WorkspaceDirectoryState::Deregistering => "DEREGISTERING",
            WorkspaceDirectoryState::Error => "ERROR",
            WorkspaceDirectoryState::Registered => "REGISTERED",
            WorkspaceDirectoryState::Registering => "REGISTERING",
            WorkspaceDirectoryState::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["DEREGISTERED", "DEREGISTERING", "ERROR", "REGISTERED", "REGISTERING"]
    }
}
impl ::std::convert::AsRef<str> for WorkspaceDirectoryState {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl WorkspaceDirectoryState {
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
impl ::std::fmt::Display for WorkspaceDirectoryState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            WorkspaceDirectoryState::Deregistered => write!(f, "DEREGISTERED"),
            WorkspaceDirectoryState::Deregistering => write!(f, "DEREGISTERING"),
            WorkspaceDirectoryState::Error => write!(f, "ERROR"),
            WorkspaceDirectoryState::Registered => write!(f, "REGISTERED"),
            WorkspaceDirectoryState::Registering => write!(f, "REGISTERING"),
            WorkspaceDirectoryState::Unknown(value) => write!(f, "{}", value),
        }
    }
}
