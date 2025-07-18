// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `ModelStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let modelstatus = unimplemented!();
/// match modelstatus {
///     ModelStatus::Deleting => { /* ... */ },
///     ModelStatus::Hosted => { /* ... */ },
///     ModelStatus::HostingFailed => { /* ... */ },
///     ModelStatus::StartingHosting => { /* ... */ },
///     ModelStatus::StoppingHosting => { /* ... */ },
///     ModelStatus::SystemUpdating => { /* ... */ },
///     ModelStatus::Trained => { /* ... */ },
///     ModelStatus::Training => { /* ... */ },
///     ModelStatus::TrainingFailed => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `modelstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `ModelStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `ModelStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `ModelStatus::NewFeature` is defined.
/// Specifically, when `modelstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `ModelStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum ModelStatus {
    #[allow(missing_docs)] // documentation missing in model
    Deleting,
    #[allow(missing_docs)] // documentation missing in model
    Hosted,
    #[allow(missing_docs)] // documentation missing in model
    HostingFailed,
    #[allow(missing_docs)] // documentation missing in model
    StartingHosting,
    #[allow(missing_docs)] // documentation missing in model
    StoppingHosting,
    #[allow(missing_docs)] // documentation missing in model
    SystemUpdating,
    #[allow(missing_docs)] // documentation missing in model
    Trained,
    #[allow(missing_docs)] // documentation missing in model
    Training,
    #[allow(missing_docs)] // documentation missing in model
    TrainingFailed,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for ModelStatus {
    fn from(s: &str) -> Self {
        match s {
            "DELETING" => ModelStatus::Deleting,
            "HOSTED" => ModelStatus::Hosted,
            "HOSTING_FAILED" => ModelStatus::HostingFailed,
            "STARTING_HOSTING" => ModelStatus::StartingHosting,
            "STOPPING_HOSTING" => ModelStatus::StoppingHosting,
            "SYSTEM_UPDATING" => ModelStatus::SystemUpdating,
            "TRAINED" => ModelStatus::Trained,
            "TRAINING" => ModelStatus::Training,
            "TRAINING_FAILED" => ModelStatus::TrainingFailed,
            other => ModelStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for ModelStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(ModelStatus::from(s))
    }
}
impl ModelStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            ModelStatus::Deleting => "DELETING",
            ModelStatus::Hosted => "HOSTED",
            ModelStatus::HostingFailed => "HOSTING_FAILED",
            ModelStatus::StartingHosting => "STARTING_HOSTING",
            ModelStatus::StoppingHosting => "STOPPING_HOSTING",
            ModelStatus::SystemUpdating => "SYSTEM_UPDATING",
            ModelStatus::Trained => "TRAINED",
            ModelStatus::Training => "TRAINING",
            ModelStatus::TrainingFailed => "TRAINING_FAILED",
            ModelStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "DELETING",
            "HOSTED",
            "HOSTING_FAILED",
            "STARTING_HOSTING",
            "STOPPING_HOSTING",
            "SYSTEM_UPDATING",
            "TRAINED",
            "TRAINING",
            "TRAINING_FAILED",
        ]
    }
}
impl ::std::convert::AsRef<str> for ModelStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl ModelStatus {
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
impl ::std::fmt::Display for ModelStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            ModelStatus::Deleting => write!(f, "DELETING"),
            ModelStatus::Hosted => write!(f, "HOSTED"),
            ModelStatus::HostingFailed => write!(f, "HOSTING_FAILED"),
            ModelStatus::StartingHosting => write!(f, "STARTING_HOSTING"),
            ModelStatus::StoppingHosting => write!(f, "STOPPING_HOSTING"),
            ModelStatus::SystemUpdating => write!(f, "SYSTEM_UPDATING"),
            ModelStatus::Trained => write!(f, "TRAINED"),
            ModelStatus::Training => write!(f, "TRAINING"),
            ModelStatus::TrainingFailed => write!(f, "TRAINING_FAILED"),
            ModelStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
