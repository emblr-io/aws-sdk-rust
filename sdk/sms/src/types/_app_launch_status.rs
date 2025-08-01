// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AppLaunchStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let applaunchstatus = unimplemented!();
/// match applaunchstatus {
///     AppLaunchStatus::ConfigurationInvalid => { /* ... */ },
///     AppLaunchStatus::ConfigurationInProgress => { /* ... */ },
///     AppLaunchStatus::DeltaLaunchFailed => { /* ... */ },
///     AppLaunchStatus::DeltaLaunchInProgress => { /* ... */ },
///     AppLaunchStatus::Launched => { /* ... */ },
///     AppLaunchStatus::LaunchFailed => { /* ... */ },
///     AppLaunchStatus::LaunchInProgress => { /* ... */ },
///     AppLaunchStatus::LaunchPending => { /* ... */ },
///     AppLaunchStatus::PartiallyLaunched => { /* ... */ },
///     AppLaunchStatus::ReadyForConfiguration => { /* ... */ },
///     AppLaunchStatus::ReadyForLaunch => { /* ... */ },
///     AppLaunchStatus::Terminated => { /* ... */ },
///     AppLaunchStatus::TerminateFailed => { /* ... */ },
///     AppLaunchStatus::TerminateInProgress => { /* ... */ },
///     AppLaunchStatus::ValidationInProgress => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `applaunchstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AppLaunchStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AppLaunchStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AppLaunchStatus::NewFeature` is defined.
/// Specifically, when `applaunchstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AppLaunchStatus::NewFeature` also yielding `"NewFeature"`.
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
pub enum AppLaunchStatus {
    #[allow(missing_docs)] // documentation missing in model
    ConfigurationInvalid,
    #[allow(missing_docs)] // documentation missing in model
    ConfigurationInProgress,
    #[allow(missing_docs)] // documentation missing in model
    DeltaLaunchFailed,
    #[allow(missing_docs)] // documentation missing in model
    DeltaLaunchInProgress,
    #[allow(missing_docs)] // documentation missing in model
    Launched,
    #[allow(missing_docs)] // documentation missing in model
    LaunchFailed,
    #[allow(missing_docs)] // documentation missing in model
    LaunchInProgress,
    #[allow(missing_docs)] // documentation missing in model
    LaunchPending,
    #[allow(missing_docs)] // documentation missing in model
    PartiallyLaunched,
    #[allow(missing_docs)] // documentation missing in model
    ReadyForConfiguration,
    #[allow(missing_docs)] // documentation missing in model
    ReadyForLaunch,
    #[allow(missing_docs)] // documentation missing in model
    Terminated,
    #[allow(missing_docs)] // documentation missing in model
    TerminateFailed,
    #[allow(missing_docs)] // documentation missing in model
    TerminateInProgress,
    #[allow(missing_docs)] // documentation missing in model
    ValidationInProgress,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AppLaunchStatus {
    fn from(s: &str) -> Self {
        match s {
            "CONFIGURATION_INVALID" => AppLaunchStatus::ConfigurationInvalid,
            "CONFIGURATION_IN_PROGRESS" => AppLaunchStatus::ConfigurationInProgress,
            "DELTA_LAUNCH_FAILED" => AppLaunchStatus::DeltaLaunchFailed,
            "DELTA_LAUNCH_IN_PROGRESS" => AppLaunchStatus::DeltaLaunchInProgress,
            "LAUNCHED" => AppLaunchStatus::Launched,
            "LAUNCH_FAILED" => AppLaunchStatus::LaunchFailed,
            "LAUNCH_IN_PROGRESS" => AppLaunchStatus::LaunchInProgress,
            "LAUNCH_PENDING" => AppLaunchStatus::LaunchPending,
            "PARTIALLY_LAUNCHED" => AppLaunchStatus::PartiallyLaunched,
            "READY_FOR_CONFIGURATION" => AppLaunchStatus::ReadyForConfiguration,
            "READY_FOR_LAUNCH" => AppLaunchStatus::ReadyForLaunch,
            "TERMINATED" => AppLaunchStatus::Terminated,
            "TERMINATE_FAILED" => AppLaunchStatus::TerminateFailed,
            "TERMINATE_IN_PROGRESS" => AppLaunchStatus::TerminateInProgress,
            "VALIDATION_IN_PROGRESS" => AppLaunchStatus::ValidationInProgress,
            other => AppLaunchStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AppLaunchStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AppLaunchStatus::from(s))
    }
}
impl AppLaunchStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AppLaunchStatus::ConfigurationInvalid => "CONFIGURATION_INVALID",
            AppLaunchStatus::ConfigurationInProgress => "CONFIGURATION_IN_PROGRESS",
            AppLaunchStatus::DeltaLaunchFailed => "DELTA_LAUNCH_FAILED",
            AppLaunchStatus::DeltaLaunchInProgress => "DELTA_LAUNCH_IN_PROGRESS",
            AppLaunchStatus::Launched => "LAUNCHED",
            AppLaunchStatus::LaunchFailed => "LAUNCH_FAILED",
            AppLaunchStatus::LaunchInProgress => "LAUNCH_IN_PROGRESS",
            AppLaunchStatus::LaunchPending => "LAUNCH_PENDING",
            AppLaunchStatus::PartiallyLaunched => "PARTIALLY_LAUNCHED",
            AppLaunchStatus::ReadyForConfiguration => "READY_FOR_CONFIGURATION",
            AppLaunchStatus::ReadyForLaunch => "READY_FOR_LAUNCH",
            AppLaunchStatus::Terminated => "TERMINATED",
            AppLaunchStatus::TerminateFailed => "TERMINATE_FAILED",
            AppLaunchStatus::TerminateInProgress => "TERMINATE_IN_PROGRESS",
            AppLaunchStatus::ValidationInProgress => "VALIDATION_IN_PROGRESS",
            AppLaunchStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "CONFIGURATION_INVALID",
            "CONFIGURATION_IN_PROGRESS",
            "DELTA_LAUNCH_FAILED",
            "DELTA_LAUNCH_IN_PROGRESS",
            "LAUNCHED",
            "LAUNCH_FAILED",
            "LAUNCH_IN_PROGRESS",
            "LAUNCH_PENDING",
            "PARTIALLY_LAUNCHED",
            "READY_FOR_CONFIGURATION",
            "READY_FOR_LAUNCH",
            "TERMINATED",
            "TERMINATE_FAILED",
            "TERMINATE_IN_PROGRESS",
            "VALIDATION_IN_PROGRESS",
        ]
    }
}
impl ::std::convert::AsRef<str> for AppLaunchStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AppLaunchStatus {
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
impl ::std::fmt::Display for AppLaunchStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AppLaunchStatus::ConfigurationInvalid => write!(f, "CONFIGURATION_INVALID"),
            AppLaunchStatus::ConfigurationInProgress => write!(f, "CONFIGURATION_IN_PROGRESS"),
            AppLaunchStatus::DeltaLaunchFailed => write!(f, "DELTA_LAUNCH_FAILED"),
            AppLaunchStatus::DeltaLaunchInProgress => write!(f, "DELTA_LAUNCH_IN_PROGRESS"),
            AppLaunchStatus::Launched => write!(f, "LAUNCHED"),
            AppLaunchStatus::LaunchFailed => write!(f, "LAUNCH_FAILED"),
            AppLaunchStatus::LaunchInProgress => write!(f, "LAUNCH_IN_PROGRESS"),
            AppLaunchStatus::LaunchPending => write!(f, "LAUNCH_PENDING"),
            AppLaunchStatus::PartiallyLaunched => write!(f, "PARTIALLY_LAUNCHED"),
            AppLaunchStatus::ReadyForConfiguration => write!(f, "READY_FOR_CONFIGURATION"),
            AppLaunchStatus::ReadyForLaunch => write!(f, "READY_FOR_LAUNCH"),
            AppLaunchStatus::Terminated => write!(f, "TERMINATED"),
            AppLaunchStatus::TerminateFailed => write!(f, "TERMINATE_FAILED"),
            AppLaunchStatus::TerminateInProgress => write!(f, "TERMINATE_IN_PROGRESS"),
            AppLaunchStatus::ValidationInProgress => write!(f, "VALIDATION_IN_PROGRESS"),
            AppLaunchStatus::Unknown(value) => write!(f, "{}", value),
        }
    }
}
