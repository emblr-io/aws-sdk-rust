// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The settings to configure your license server.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LicenseServerSettings {
    /// <p>The type of license server.</p>
    pub server_type: crate::types::ServerType,
    /// <p>The <code>ServerSettings</code> resource contains the settings for your server.</p>
    pub server_settings: ::std::option::Option<crate::types::ServerSettings>,
}
impl LicenseServerSettings {
    /// <p>The type of license server.</p>
    pub fn server_type(&self) -> &crate::types::ServerType {
        &self.server_type
    }
    /// <p>The <code>ServerSettings</code> resource contains the settings for your server.</p>
    pub fn server_settings(&self) -> ::std::option::Option<&crate::types::ServerSettings> {
        self.server_settings.as_ref()
    }
}
impl LicenseServerSettings {
    /// Creates a new builder-style object to manufacture [`LicenseServerSettings`](crate::types::LicenseServerSettings).
    pub fn builder() -> crate::types::builders::LicenseServerSettingsBuilder {
        crate::types::builders::LicenseServerSettingsBuilder::default()
    }
}

/// A builder for [`LicenseServerSettings`](crate::types::LicenseServerSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LicenseServerSettingsBuilder {
    pub(crate) server_type: ::std::option::Option<crate::types::ServerType>,
    pub(crate) server_settings: ::std::option::Option<crate::types::ServerSettings>,
}
impl LicenseServerSettingsBuilder {
    /// <p>The type of license server.</p>
    /// This field is required.
    pub fn server_type(mut self, input: crate::types::ServerType) -> Self {
        self.server_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of license server.</p>
    pub fn set_server_type(mut self, input: ::std::option::Option<crate::types::ServerType>) -> Self {
        self.server_type = input;
        self
    }
    /// <p>The type of license server.</p>
    pub fn get_server_type(&self) -> &::std::option::Option<crate::types::ServerType> {
        &self.server_type
    }
    /// <p>The <code>ServerSettings</code> resource contains the settings for your server.</p>
    /// This field is required.
    pub fn server_settings(mut self, input: crate::types::ServerSettings) -> Self {
        self.server_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>ServerSettings</code> resource contains the settings for your server.</p>
    pub fn set_server_settings(mut self, input: ::std::option::Option<crate::types::ServerSettings>) -> Self {
        self.server_settings = input;
        self
    }
    /// <p>The <code>ServerSettings</code> resource contains the settings for your server.</p>
    pub fn get_server_settings(&self) -> &::std::option::Option<crate::types::ServerSettings> {
        &self.server_settings
    }
    /// Consumes the builder and constructs a [`LicenseServerSettings`](crate::types::LicenseServerSettings).
    /// This method will fail if any of the following fields are not set:
    /// - [`server_type`](crate::types::builders::LicenseServerSettingsBuilder::server_type)
    pub fn build(self) -> ::std::result::Result<crate::types::LicenseServerSettings, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LicenseServerSettings {
            server_type: self.server_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "server_type",
                    "server_type was not specified but it is required when building LicenseServerSettings",
                )
            })?,
            server_settings: self.server_settings,
        })
    }
}
