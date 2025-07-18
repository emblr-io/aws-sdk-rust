// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure containing information about how this workspace works with SAML.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SamlAuthentication {
    /// <p>Specifies whether the workspace's SAML configuration is complete.</p>
    pub status: crate::types::SamlConfigurationStatus,
    /// <p>A structure containing details about how this workspace works with SAML.</p>
    pub configuration: ::std::option::Option<crate::types::SamlConfiguration>,
}
impl SamlAuthentication {
    /// <p>Specifies whether the workspace's SAML configuration is complete.</p>
    pub fn status(&self) -> &crate::types::SamlConfigurationStatus {
        &self.status
    }
    /// <p>A structure containing details about how this workspace works with SAML.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::SamlConfiguration> {
        self.configuration.as_ref()
    }
}
impl SamlAuthentication {
    /// Creates a new builder-style object to manufacture [`SamlAuthentication`](crate::types::SamlAuthentication).
    pub fn builder() -> crate::types::builders::SamlAuthenticationBuilder {
        crate::types::builders::SamlAuthenticationBuilder::default()
    }
}

/// A builder for [`SamlAuthentication`](crate::types::SamlAuthentication).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SamlAuthenticationBuilder {
    pub(crate) status: ::std::option::Option<crate::types::SamlConfigurationStatus>,
    pub(crate) configuration: ::std::option::Option<crate::types::SamlConfiguration>,
}
impl SamlAuthenticationBuilder {
    /// <p>Specifies whether the workspace's SAML configuration is complete.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::SamlConfigurationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the workspace's SAML configuration is complete.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SamlConfigurationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Specifies whether the workspace's SAML configuration is complete.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SamlConfigurationStatus> {
        &self.status
    }
    /// <p>A structure containing details about how this workspace works with SAML.</p>
    pub fn configuration(mut self, input: crate::types::SamlConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure containing details about how this workspace works with SAML.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::SamlConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>A structure containing details about how this workspace works with SAML.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::SamlConfiguration> {
        &self.configuration
    }
    /// Consumes the builder and constructs a [`SamlAuthentication`](crate::types::SamlAuthentication).
    /// This method will fail if any of the following fields are not set:
    /// - [`status`](crate::types::builders::SamlAuthenticationBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::SamlAuthentication, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SamlAuthentication {
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building SamlAuthentication",
                )
            })?,
            configuration: self.configuration,
        })
    }
}
