// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `NotificationRole`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let notificationrole = unimplemented!();
/// match notificationrole {
///     NotificationRole::DomainOwner => { /* ... */ },
///     NotificationRole::ProjectContributor => { /* ... */ },
///     NotificationRole::ProjectOwner => { /* ... */ },
///     NotificationRole::ProjectSubscriber => { /* ... */ },
///     NotificationRole::ProjectViewer => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `notificationrole` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `NotificationRole::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `NotificationRole::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `NotificationRole::NewFeature` is defined.
/// Specifically, when `notificationrole` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `NotificationRole::NewFeature` also yielding `"NewFeature"`.
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
pub enum NotificationRole {
    #[allow(missing_docs)] // documentation missing in model
    DomainOwner,
    #[allow(missing_docs)] // documentation missing in model
    ProjectContributor,
    #[allow(missing_docs)] // documentation missing in model
    ProjectOwner,
    #[allow(missing_docs)] // documentation missing in model
    ProjectSubscriber,
    #[allow(missing_docs)] // documentation missing in model
    ProjectViewer,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for NotificationRole {
    fn from(s: &str) -> Self {
        match s {
            "DOMAIN_OWNER" => NotificationRole::DomainOwner,
            "PROJECT_CONTRIBUTOR" => NotificationRole::ProjectContributor,
            "PROJECT_OWNER" => NotificationRole::ProjectOwner,
            "PROJECT_SUBSCRIBER" => NotificationRole::ProjectSubscriber,
            "PROJECT_VIEWER" => NotificationRole::ProjectViewer,
            other => NotificationRole::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for NotificationRole {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(NotificationRole::from(s))
    }
}
impl NotificationRole {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            NotificationRole::DomainOwner => "DOMAIN_OWNER",
            NotificationRole::ProjectContributor => "PROJECT_CONTRIBUTOR",
            NotificationRole::ProjectOwner => "PROJECT_OWNER",
            NotificationRole::ProjectSubscriber => "PROJECT_SUBSCRIBER",
            NotificationRole::ProjectViewer => "PROJECT_VIEWER",
            NotificationRole::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "DOMAIN_OWNER",
            "PROJECT_CONTRIBUTOR",
            "PROJECT_OWNER",
            "PROJECT_SUBSCRIBER",
            "PROJECT_VIEWER",
        ]
    }
}
impl ::std::convert::AsRef<str> for NotificationRole {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl NotificationRole {
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
impl ::std::fmt::Display for NotificationRole {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            NotificationRole::DomainOwner => write!(f, "DOMAIN_OWNER"),
            NotificationRole::ProjectContributor => write!(f, "PROJECT_CONTRIBUTOR"),
            NotificationRole::ProjectOwner => write!(f, "PROJECT_OWNER"),
            NotificationRole::ProjectSubscriber => write!(f, "PROJECT_SUBSCRIBER"),
            NotificationRole::ProjectViewer => write!(f, "PROJECT_VIEWER"),
            NotificationRole::Unknown(value) => write!(f, "{}", value),
        }
    }
}
