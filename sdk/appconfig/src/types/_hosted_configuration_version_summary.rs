// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HostedConfigurationVersionSummary {
    /// <p>The application ID.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The configuration profile ID.</p>
    pub configuration_profile_id: ::std::option::Option<::std::string::String>,
    /// <p>The configuration version.</p>
    pub version_number: i32,
    /// <p>A description of the configuration.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A standard MIME type describing the format of the configuration content. For more information, see <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.17">Content-Type</a>.</p>
    pub content_type: ::std::option::Option<::std::string::String>,
    /// <p>A user-defined label for an AppConfig hosted configuration version.</p>
    pub version_label: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name of the Key Management Service key that was used to encrypt this specific version of the configuration data in the AppConfig hosted configuration store.</p>
    pub kms_key_arn: ::std::option::Option<::std::string::String>,
}
impl HostedConfigurationVersionSummary {
    /// <p>The application ID.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The configuration profile ID.</p>
    pub fn configuration_profile_id(&self) -> ::std::option::Option<&str> {
        self.configuration_profile_id.as_deref()
    }
    /// <p>The configuration version.</p>
    pub fn version_number(&self) -> i32 {
        self.version_number
    }
    /// <p>A description of the configuration.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A standard MIME type describing the format of the configuration content. For more information, see <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.17">Content-Type</a>.</p>
    pub fn content_type(&self) -> ::std::option::Option<&str> {
        self.content_type.as_deref()
    }
    /// <p>A user-defined label for an AppConfig hosted configuration version.</p>
    pub fn version_label(&self) -> ::std::option::Option<&str> {
        self.version_label.as_deref()
    }
    /// <p>The Amazon Resource Name of the Key Management Service key that was used to encrypt this specific version of the configuration data in the AppConfig hosted configuration store.</p>
    pub fn kms_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_key_arn.as_deref()
    }
}
impl HostedConfigurationVersionSummary {
    /// Creates a new builder-style object to manufacture [`HostedConfigurationVersionSummary`](crate::types::HostedConfigurationVersionSummary).
    pub fn builder() -> crate::types::builders::HostedConfigurationVersionSummaryBuilder {
        crate::types::builders::HostedConfigurationVersionSummaryBuilder::default()
    }
}

/// A builder for [`HostedConfigurationVersionSummary`](crate::types::HostedConfigurationVersionSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HostedConfigurationVersionSummaryBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) configuration_profile_id: ::std::option::Option<::std::string::String>,
    pub(crate) version_number: ::std::option::Option<i32>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
    pub(crate) version_label: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
}
impl HostedConfigurationVersionSummaryBuilder {
    /// <p>The application ID.</p>
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The application ID.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The application ID.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The configuration profile ID.</p>
    pub fn configuration_profile_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_profile_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The configuration profile ID.</p>
    pub fn set_configuration_profile_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_profile_id = input;
        self
    }
    /// <p>The configuration profile ID.</p>
    pub fn get_configuration_profile_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_profile_id
    }
    /// <p>The configuration version.</p>
    pub fn version_number(mut self, input: i32) -> Self {
        self.version_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration version.</p>
    pub fn set_version_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.version_number = input;
        self
    }
    /// <p>The configuration version.</p>
    pub fn get_version_number(&self) -> &::std::option::Option<i32> {
        &self.version_number
    }
    /// <p>A description of the configuration.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the configuration.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the configuration.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A standard MIME type describing the format of the configuration content. For more information, see <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.17">Content-Type</a>.</p>
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A standard MIME type describing the format of the configuration content. For more information, see <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.17">Content-Type</a>.</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>A standard MIME type describing the format of the configuration content. For more information, see <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.17">Content-Type</a>.</p>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// <p>A user-defined label for an AppConfig hosted configuration version.</p>
    pub fn version_label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A user-defined label for an AppConfig hosted configuration version.</p>
    pub fn set_version_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_label = input;
        self
    }
    /// <p>A user-defined label for an AppConfig hosted configuration version.</p>
    pub fn get_version_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_label
    }
    /// <p>The Amazon Resource Name of the Key Management Service key that was used to encrypt this specific version of the configuration data in the AppConfig hosted configuration store.</p>
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name of the Key Management Service key that was used to encrypt this specific version of the configuration data in the AppConfig hosted configuration store.</p>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name of the Key Management Service key that was used to encrypt this specific version of the configuration data in the AppConfig hosted configuration store.</p>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    /// Consumes the builder and constructs a [`HostedConfigurationVersionSummary`](crate::types::HostedConfigurationVersionSummary).
    pub fn build(self) -> crate::types::HostedConfigurationVersionSummary {
        crate::types::HostedConfigurationVersionSummary {
            application_id: self.application_id,
            configuration_profile_id: self.configuration_profile_id,
            version_number: self.version_number.unwrap_or_default(),
            description: self.description,
            content_type: self.content_type,
            version_label: self.version_label,
            kms_key_arn: self.kms_key_arn,
        }
    }
}
