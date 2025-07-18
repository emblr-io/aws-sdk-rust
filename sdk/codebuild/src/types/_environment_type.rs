// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `EnvironmentType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let environmenttype = unimplemented!();
/// match environmenttype {
///     EnvironmentType::ArmContainer => { /* ... */ },
///     EnvironmentType::ArmEc2 => { /* ... */ },
///     EnvironmentType::ArmLambdaContainer => { /* ... */ },
///     EnvironmentType::LinuxContainer => { /* ... */ },
///     EnvironmentType::LinuxEc2 => { /* ... */ },
///     EnvironmentType::LinuxGpuContainer => { /* ... */ },
///     EnvironmentType::LinuxLambdaContainer => { /* ... */ },
///     EnvironmentType::MacArm => { /* ... */ },
///     EnvironmentType::WindowsContainer => { /* ... */ },
///     EnvironmentType::WindowsEc2 => { /* ... */ },
///     EnvironmentType::WindowsServer2019Container => { /* ... */ },
///     EnvironmentType::WindowsServer2022Container => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `environmenttype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `EnvironmentType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `EnvironmentType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `EnvironmentType::NewFeature` is defined.
/// Specifically, when `environmenttype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `EnvironmentType::NewFeature` also yielding `"NewFeature"`.
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
pub enum EnvironmentType {
    #[allow(missing_docs)] // documentation missing in model
    ArmContainer,
    #[allow(missing_docs)] // documentation missing in model
    ArmEc2,
    #[allow(missing_docs)] // documentation missing in model
    ArmLambdaContainer,
    #[allow(missing_docs)] // documentation missing in model
    LinuxContainer,
    #[allow(missing_docs)] // documentation missing in model
    LinuxEc2,
    #[allow(missing_docs)] // documentation missing in model
    LinuxGpuContainer,
    #[allow(missing_docs)] // documentation missing in model
    LinuxLambdaContainer,
    #[allow(missing_docs)] // documentation missing in model
    MacArm,
    #[allow(missing_docs)] // documentation missing in model
    WindowsContainer,
    #[allow(missing_docs)] // documentation missing in model
    WindowsEc2,
    #[allow(missing_docs)] // documentation missing in model
    WindowsServer2019Container,
    #[allow(missing_docs)] // documentation missing in model
    WindowsServer2022Container,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for EnvironmentType {
    fn from(s: &str) -> Self {
        match s {
            "ARM_CONTAINER" => EnvironmentType::ArmContainer,
            "ARM_EC2" => EnvironmentType::ArmEc2,
            "ARM_LAMBDA_CONTAINER" => EnvironmentType::ArmLambdaContainer,
            "LINUX_CONTAINER" => EnvironmentType::LinuxContainer,
            "LINUX_EC2" => EnvironmentType::LinuxEc2,
            "LINUX_GPU_CONTAINER" => EnvironmentType::LinuxGpuContainer,
            "LINUX_LAMBDA_CONTAINER" => EnvironmentType::LinuxLambdaContainer,
            "MAC_ARM" => EnvironmentType::MacArm,
            "WINDOWS_CONTAINER" => EnvironmentType::WindowsContainer,
            "WINDOWS_EC2" => EnvironmentType::WindowsEc2,
            "WINDOWS_SERVER_2019_CONTAINER" => EnvironmentType::WindowsServer2019Container,
            "WINDOWS_SERVER_2022_CONTAINER" => EnvironmentType::WindowsServer2022Container,
            other => EnvironmentType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for EnvironmentType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(EnvironmentType::from(s))
    }
}
impl EnvironmentType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            EnvironmentType::ArmContainer => "ARM_CONTAINER",
            EnvironmentType::ArmEc2 => "ARM_EC2",
            EnvironmentType::ArmLambdaContainer => "ARM_LAMBDA_CONTAINER",
            EnvironmentType::LinuxContainer => "LINUX_CONTAINER",
            EnvironmentType::LinuxEc2 => "LINUX_EC2",
            EnvironmentType::LinuxGpuContainer => "LINUX_GPU_CONTAINER",
            EnvironmentType::LinuxLambdaContainer => "LINUX_LAMBDA_CONTAINER",
            EnvironmentType::MacArm => "MAC_ARM",
            EnvironmentType::WindowsContainer => "WINDOWS_CONTAINER",
            EnvironmentType::WindowsEc2 => "WINDOWS_EC2",
            EnvironmentType::WindowsServer2019Container => "WINDOWS_SERVER_2019_CONTAINER",
            EnvironmentType::WindowsServer2022Container => "WINDOWS_SERVER_2022_CONTAINER",
            EnvironmentType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ARM_CONTAINER",
            "ARM_EC2",
            "ARM_LAMBDA_CONTAINER",
            "LINUX_CONTAINER",
            "LINUX_EC2",
            "LINUX_GPU_CONTAINER",
            "LINUX_LAMBDA_CONTAINER",
            "MAC_ARM",
            "WINDOWS_CONTAINER",
            "WINDOWS_EC2",
            "WINDOWS_SERVER_2019_CONTAINER",
            "WINDOWS_SERVER_2022_CONTAINER",
        ]
    }
}
impl ::std::convert::AsRef<str> for EnvironmentType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl EnvironmentType {
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
impl ::std::fmt::Display for EnvironmentType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            EnvironmentType::ArmContainer => write!(f, "ARM_CONTAINER"),
            EnvironmentType::ArmEc2 => write!(f, "ARM_EC2"),
            EnvironmentType::ArmLambdaContainer => write!(f, "ARM_LAMBDA_CONTAINER"),
            EnvironmentType::LinuxContainer => write!(f, "LINUX_CONTAINER"),
            EnvironmentType::LinuxEc2 => write!(f, "LINUX_EC2"),
            EnvironmentType::LinuxGpuContainer => write!(f, "LINUX_GPU_CONTAINER"),
            EnvironmentType::LinuxLambdaContainer => write!(f, "LINUX_LAMBDA_CONTAINER"),
            EnvironmentType::MacArm => write!(f, "MAC_ARM"),
            EnvironmentType::WindowsContainer => write!(f, "WINDOWS_CONTAINER"),
            EnvironmentType::WindowsEc2 => write!(f, "WINDOWS_EC2"),
            EnvironmentType::WindowsServer2019Container => write!(f, "WINDOWS_SERVER_2019_CONTAINER"),
            EnvironmentType::WindowsServer2022Container => write!(f, "WINDOWS_SERVER_2022_CONTAINER"),
            EnvironmentType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
