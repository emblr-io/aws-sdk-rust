// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `Ec2InstanceState`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let ec2instancestate = unimplemented!();
/// match ec2instancestate {
///     Ec2InstanceState::NotFound => { /* ... */ },
///     Ec2InstanceState::Pending => { /* ... */ },
///     Ec2InstanceState::Running => { /* ... */ },
///     Ec2InstanceState::ShuttingDown => { /* ... */ },
///     Ec2InstanceState::Stopped => { /* ... */ },
///     Ec2InstanceState::Stopping => { /* ... */ },
///     Ec2InstanceState::Terminated => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `ec2instancestate` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `Ec2InstanceState::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `Ec2InstanceState::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `Ec2InstanceState::NewFeature` is defined.
/// Specifically, when `ec2instancestate` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `Ec2InstanceState::NewFeature` also yielding `"NewFeature"`.
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
pub enum Ec2InstanceState {
    #[allow(missing_docs)] // documentation missing in model
    NotFound,
    #[allow(missing_docs)] // documentation missing in model
    Pending,
    #[allow(missing_docs)] // documentation missing in model
    Running,
    #[allow(missing_docs)] // documentation missing in model
    ShuttingDown,
    #[allow(missing_docs)] // documentation missing in model
    Stopped,
    #[allow(missing_docs)] // documentation missing in model
    Stopping,
    #[allow(missing_docs)] // documentation missing in model
    Terminated,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for Ec2InstanceState {
    fn from(s: &str) -> Self {
        match s {
            "NOT_FOUND" => Ec2InstanceState::NotFound,
            "PENDING" => Ec2InstanceState::Pending,
            "RUNNING" => Ec2InstanceState::Running,
            "SHUTTING-DOWN" => Ec2InstanceState::ShuttingDown,
            "STOPPED" => Ec2InstanceState::Stopped,
            "STOPPING" => Ec2InstanceState::Stopping,
            "TERMINATED" => Ec2InstanceState::Terminated,
            other => Ec2InstanceState::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for Ec2InstanceState {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(Ec2InstanceState::from(s))
    }
}
impl Ec2InstanceState {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            Ec2InstanceState::NotFound => "NOT_FOUND",
            Ec2InstanceState::Pending => "PENDING",
            Ec2InstanceState::Running => "RUNNING",
            Ec2InstanceState::ShuttingDown => "SHUTTING-DOWN",
            Ec2InstanceState::Stopped => "STOPPED",
            Ec2InstanceState::Stopping => "STOPPING",
            Ec2InstanceState::Terminated => "TERMINATED",
            Ec2InstanceState::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &["NOT_FOUND", "PENDING", "RUNNING", "SHUTTING-DOWN", "STOPPED", "STOPPING", "TERMINATED"]
    }
}
impl ::std::convert::AsRef<str> for Ec2InstanceState {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Ec2InstanceState {
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
impl ::std::fmt::Display for Ec2InstanceState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            Ec2InstanceState::NotFound => write!(f, "NOT_FOUND"),
            Ec2InstanceState::Pending => write!(f, "PENDING"),
            Ec2InstanceState::Running => write!(f, "RUNNING"),
            Ec2InstanceState::ShuttingDown => write!(f, "SHUTTING-DOWN"),
            Ec2InstanceState::Stopped => write!(f, "STOPPED"),
            Ec2InstanceState::Stopping => write!(f, "STOPPING"),
            Ec2InstanceState::Terminated => write!(f, "TERMINATED"),
            Ec2InstanceState::Unknown(value) => write!(f, "{}", value),
        }
    }
}
