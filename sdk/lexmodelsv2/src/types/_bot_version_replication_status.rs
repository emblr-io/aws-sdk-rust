// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `BotVersionReplicationStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let botversionreplicationstatus = unimplemented!();
/// match botversionreplicationstatus {
///     BotVersionReplicationStatus::Available => { /* ... */ },
///     BotVersionReplicationStatus::Creating => { /* ... */ },
///     BotVersionReplicationStatus::Deleting => { /* ... */ },
///     BotVersionReplicationStatus::Failed => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `botversionreplicationstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `BotVersionReplicationStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `BotVersionReplicationStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `BotVersionReplicationStatus::NewFeature` is defined.
/// Specifically, when `botversionreplicationstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `BotVersionReplicationStatus::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
/// <p>The status of the operation to replicate the bot version. Values: Creating, Available, Deleting, Failed.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum BotVersionReplicationStatus {
    #[allow(missing_docs)] // documentation missing in model
    Available,
    #[allow(missing_docs)] // documentation missing in model
    Creating,
    #[allow(missing_docs)] // documentation missing in model
    Deleting,
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for BotVersionReplicationStatus {
    fn from(s: &str) -> Self {
        match s {
            "Available" => BotVersionReplicationStatus::Available,
            "Creating" => BotVersionReplicationStatus::Creating,
            "Deleting" => BotVersionReplicationStatus::Deleting,
            "Failed" => BotVersionReplicationStatus::Failed,
            other => BotVersionReplicationStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for BotVersionReplicationStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(BotVersionReplicationStatus::from(s))
    }
}
impl BotVersionReplicationStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            BotVersionReplicationStatus::Available => "Available",
            BotVersionReplicationStatus::Creating => "Creating",
            BotVersionReplicationStatus::Deleting => "Deleting",
            BotVersionReplicationStatus::Failed => "Failed",
            BotVersionReplicationStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["Available", "Creating", "Deleting", "Failed"]
    }
}
impl ::std::convert::AsRef<str> for BotVersionReplicationStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl BotVersionReplicationStatus {
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
impl ::std::fmt::Display for BotVersionReplicationStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            BotVersionReplicationStatus::Available => write!(f, "Available"),
            BotVersionReplicationStatus::Creating => write!(f, "Creating"),
            BotVersionReplicationStatus::Deleting => write!(f, "Deleting"),
            BotVersionReplicationStatus::Failed => write!(f, "Failed"),
            BotVersionReplicationStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
