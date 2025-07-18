// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `OperatingSystemName`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let operatingsystemname = unimplemented!();
/// match operatingsystemname {
///     OperatingSystemName::AmazonLinux2 => { /* ... */ },
///     OperatingSystemName::Rhel8 => { /* ... */ },
///     OperatingSystemName::Rocky8 => { /* ... */ },
///     OperatingSystemName::Ubuntu1804 => { /* ... */ },
///     OperatingSystemName::Ubuntu2004 => { /* ... */ },
///     OperatingSystemName::Ubuntu2204 => { /* ... */ },
///     OperatingSystemName::UnknownValue => { /* ... */ },
///     OperatingSystemName::Windows10 => { /* ... */ },
///     OperatingSystemName::Windows11 => { /* ... */ },
///     OperatingSystemName::Windows7 => { /* ... */ },
///     OperatingSystemName::WindowsServer2016 => { /* ... */ },
///     OperatingSystemName::WindowsServer2019 => { /* ... */ },
///     OperatingSystemName::WindowsServer2022 => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `operatingsystemname` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `OperatingSystemName::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `OperatingSystemName::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `OperatingSystemName::NewFeature` is defined.
/// Specifically, when `operatingsystemname` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `OperatingSystemName::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
///
/// _Note: `OperatingSystemName::Unknown` has been renamed to `::UnknownValue`._
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum OperatingSystemName {
    #[allow(missing_docs)] // documentation missing in model
    AmazonLinux2,
    #[allow(missing_docs)] // documentation missing in model
    Rhel8,
    #[allow(missing_docs)] // documentation missing in model
    Rocky8,
    #[allow(missing_docs)] // documentation missing in model
    Ubuntu1804,
    #[allow(missing_docs)] // documentation missing in model
    Ubuntu2004,
    #[allow(missing_docs)] // documentation missing in model
    Ubuntu2204,
    ///
    /// _Note: `::Unknown` has been renamed to `::UnknownValue`._
    UnknownValue,
    #[allow(missing_docs)] // documentation missing in model
    Windows10,
    #[allow(missing_docs)] // documentation missing in model
    Windows11,
    #[allow(missing_docs)] // documentation missing in model
    Windows7,
    #[allow(missing_docs)] // documentation missing in model
    WindowsServer2016,
    #[allow(missing_docs)] // documentation missing in model
    WindowsServer2019,
    #[allow(missing_docs)] // documentation missing in model
    WindowsServer2022,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for OperatingSystemName {
    fn from(s: &str) -> Self {
        match s {
            "AMAZON_LINUX_2" => OperatingSystemName::AmazonLinux2,
            "RHEL_8" => OperatingSystemName::Rhel8,
            "ROCKY_8" => OperatingSystemName::Rocky8,
            "UBUNTU_18_04" => OperatingSystemName::Ubuntu1804,
            "UBUNTU_20_04" => OperatingSystemName::Ubuntu2004,
            "UBUNTU_22_04" => OperatingSystemName::Ubuntu2204,
            "UNKNOWN" => OperatingSystemName::UnknownValue,
            "WINDOWS_10" => OperatingSystemName::Windows10,
            "WINDOWS_11" => OperatingSystemName::Windows11,
            "WINDOWS_7" => OperatingSystemName::Windows7,
            "WINDOWS_SERVER_2016" => OperatingSystemName::WindowsServer2016,
            "WINDOWS_SERVER_2019" => OperatingSystemName::WindowsServer2019,
            "WINDOWS_SERVER_2022" => OperatingSystemName::WindowsServer2022,
            other => OperatingSystemName::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for OperatingSystemName {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(OperatingSystemName::from(s))
    }
}
impl OperatingSystemName {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            OperatingSystemName::AmazonLinux2 => "AMAZON_LINUX_2",
            OperatingSystemName::Rhel8 => "RHEL_8",
            OperatingSystemName::Rocky8 => "ROCKY_8",
            OperatingSystemName::Ubuntu1804 => "UBUNTU_18_04",
            OperatingSystemName::Ubuntu2004 => "UBUNTU_20_04",
            OperatingSystemName::Ubuntu2204 => "UBUNTU_22_04",
            OperatingSystemName::UnknownValue => "UNKNOWN",
            OperatingSystemName::Windows10 => "WINDOWS_10",
            OperatingSystemName::Windows11 => "WINDOWS_11",
            OperatingSystemName::Windows7 => "WINDOWS_7",
            OperatingSystemName::WindowsServer2016 => "WINDOWS_SERVER_2016",
            OperatingSystemName::WindowsServer2019 => "WINDOWS_SERVER_2019",
            OperatingSystemName::WindowsServer2022 => "WINDOWS_SERVER_2022",
            OperatingSystemName::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AMAZON_LINUX_2",
            "RHEL_8",
            "ROCKY_8",
            "UBUNTU_18_04",
            "UBUNTU_20_04",
            "UBUNTU_22_04",
            "UNKNOWN",
            "WINDOWS_10",
            "WINDOWS_11",
            "WINDOWS_7",
            "WINDOWS_SERVER_2016",
            "WINDOWS_SERVER_2019",
            "WINDOWS_SERVER_2022",
        ]
    }
}
impl ::std::convert::AsRef<str> for OperatingSystemName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl OperatingSystemName {
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
impl ::std::fmt::Display for OperatingSystemName {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            OperatingSystemName::AmazonLinux2 => write!(f, "AMAZON_LINUX_2"),
            OperatingSystemName::Rhel8 => write!(f, "RHEL_8"),
            OperatingSystemName::Rocky8 => write!(f, "ROCKY_8"),
            OperatingSystemName::Ubuntu1804 => write!(f, "UBUNTU_18_04"),
            OperatingSystemName::Ubuntu2004 => write!(f, "UBUNTU_20_04"),
            OperatingSystemName::Ubuntu2204 => write!(f, "UBUNTU_22_04"),
            OperatingSystemName::UnknownValue => write!(f, "UNKNOWN"),
            OperatingSystemName::Windows10 => write!(f, "WINDOWS_10"),
            OperatingSystemName::Windows11 => write!(f, "WINDOWS_11"),
            OperatingSystemName::Windows7 => write!(f, "WINDOWS_7"),
            OperatingSystemName::WindowsServer2016 => write!(f, "WINDOWS_SERVER_2016"),
            OperatingSystemName::WindowsServer2019 => write!(f, "WINDOWS_SERVER_2019"),
            OperatingSystemName::WindowsServer2022 => write!(f, "WINDOWS_SERVER_2022"),
            OperatingSystemName::Unknown(value) => write!(f, "{}", value),
        }
    }
}
