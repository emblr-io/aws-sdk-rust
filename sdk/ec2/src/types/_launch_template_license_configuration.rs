// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a license configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateLicenseConfiguration {
    /// <p>The Amazon Resource Name (ARN) of the license configuration.</p>
    pub license_configuration_arn: ::std::option::Option<::std::string::String>,
}
impl LaunchTemplateLicenseConfiguration {
    /// <p>The Amazon Resource Name (ARN) of the license configuration.</p>
    pub fn license_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.license_configuration_arn.as_deref()
    }
}
impl LaunchTemplateLicenseConfiguration {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateLicenseConfiguration`](crate::types::LaunchTemplateLicenseConfiguration).
    pub fn builder() -> crate::types::builders::LaunchTemplateLicenseConfigurationBuilder {
        crate::types::builders::LaunchTemplateLicenseConfigurationBuilder::default()
    }
}

/// A builder for [`LaunchTemplateLicenseConfiguration`](crate::types::LaunchTemplateLicenseConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateLicenseConfigurationBuilder {
    pub(crate) license_configuration_arn: ::std::option::Option<::std::string::String>,
}
impl LaunchTemplateLicenseConfigurationBuilder {
    /// <p>The Amazon Resource Name (ARN) of the license configuration.</p>
    pub fn license_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the license configuration.</p>
    pub fn set_license_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the license configuration.</p>
    pub fn get_license_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_configuration_arn
    }
    /// Consumes the builder and constructs a [`LaunchTemplateLicenseConfiguration`](crate::types::LaunchTemplateLicenseConfiguration).
    pub fn build(self) -> crate::types::LaunchTemplateLicenseConfiguration {
        crate::types::LaunchTemplateLicenseConfiguration {
            license_configuration_arn: self.license_configuration_arn,
        }
    }
}
