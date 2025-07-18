// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetWebExperienceOutput {
    /// <p>The identifier of the Amazon Q Business application linked to the web experience.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the Amazon Q Business web experience.</p>
    pub web_experience_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the Amazon Q Business web experience and required resources.</p>
    pub web_experience_arn: ::std::option::Option<::std::string::String>,
    /// <p>The endpoint of your Amazon Q Business web experience.</p>
    pub default_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the Amazon Q Business web experience. When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub status: ::std::option::Option<crate::types::WebExperienceStatus>,
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The title for your Amazon Q Business web experience.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>The subtitle for your Amazon Q Business web experience.</p>
    pub subtitle: ::std::option::Option<::std::string::String>,
    /// <p>The customized welcome message for end users of an Amazon Q Business web experience.</p>
    pub welcome_message: ::std::option::Option<::std::string::String>,
    /// <p>Determines whether sample prompts are enabled in the web experience for an end user.</p>
    pub sample_prompts_control_mode: ::std::option::Option<crate::types::WebExperienceSamplePromptsControlMode>,
    /// <p>Gets the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the base URL for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p>
    pub origins: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) of the service role attached to your web experience.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Information about the identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
    pub identity_provider_configuration: ::std::option::Option<crate::types::IdentityProviderConfiguration>,
    /// <p>The authentication configuration information for your Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub authentication_configuration: ::std::option::Option<crate::types::WebExperienceAuthConfiguration>,
    /// <p>When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub error: ::std::option::Option<crate::types::ErrorDetail>,
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p>
    pub browser_extension_configuration: ::std::option::Option<crate::types::BrowserExtensionConfiguration>,
    /// <p>Gets the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub customization_configuration: ::std::option::Option<crate::types::CustomizationConfiguration>,
    _request_id: Option<String>,
}
impl GetWebExperienceOutput {
    /// <p>The identifier of the Amazon Q Business application linked to the web experience.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The identifier of the Amazon Q Business web experience.</p>
    pub fn web_experience_id(&self) -> ::std::option::Option<&str> {
        self.web_experience_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the Amazon Q Business web experience and required resources.</p>
    pub fn web_experience_arn(&self) -> ::std::option::Option<&str> {
        self.web_experience_arn.as_deref()
    }
    /// <p>The endpoint of your Amazon Q Business web experience.</p>
    pub fn default_endpoint(&self) -> ::std::option::Option<&str> {
        self.default_endpoint.as_deref()
    }
    /// <p>The current status of the Amazon Q Business web experience. When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::WebExperienceStatus> {
        self.status.as_ref()
    }
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>The title for your Amazon Q Business web experience.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>The subtitle for your Amazon Q Business web experience.</p>
    pub fn subtitle(&self) -> ::std::option::Option<&str> {
        self.subtitle.as_deref()
    }
    /// <p>The customized welcome message for end users of an Amazon Q Business web experience.</p>
    pub fn welcome_message(&self) -> ::std::option::Option<&str> {
        self.welcome_message.as_deref()
    }
    /// <p>Determines whether sample prompts are enabled in the web experience for an end user.</p>
    pub fn sample_prompts_control_mode(&self) -> ::std::option::Option<&crate::types::WebExperienceSamplePromptsControlMode> {
        self.sample_prompts_control_mode.as_ref()
    }
    /// <p>Gets the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the base URL for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.origins.is_none()`.
    pub fn origins(&self) -> &[::std::string::String] {
        self.origins.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) of the service role attached to your web experience.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>Information about the identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
    pub fn identity_provider_configuration(&self) -> ::std::option::Option<&crate::types::IdentityProviderConfiguration> {
        self.identity_provider_configuration.as_ref()
    }
    /// <p>The authentication configuration information for your Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub fn authentication_configuration(&self) -> ::std::option::Option<&crate::types::WebExperienceAuthConfiguration> {
        self.authentication_configuration.as_ref()
    }
    /// <p>When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub fn error(&self) -> ::std::option::Option<&crate::types::ErrorDetail> {
        self.error.as_ref()
    }
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p>
    pub fn browser_extension_configuration(&self) -> ::std::option::Option<&crate::types::BrowserExtensionConfiguration> {
        self.browser_extension_configuration.as_ref()
    }
    /// <p>Gets the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub fn customization_configuration(&self) -> ::std::option::Option<&crate::types::CustomizationConfiguration> {
        self.customization_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetWebExperienceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetWebExperienceOutput {
    /// Creates a new builder-style object to manufacture [`GetWebExperienceOutput`](crate::operation::get_web_experience::GetWebExperienceOutput).
    pub fn builder() -> crate::operation::get_web_experience::builders::GetWebExperienceOutputBuilder {
        crate::operation::get_web_experience::builders::GetWebExperienceOutputBuilder::default()
    }
}

/// A builder for [`GetWebExperienceOutput`](crate::operation::get_web_experience::GetWebExperienceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetWebExperienceOutputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) web_experience_id: ::std::option::Option<::std::string::String>,
    pub(crate) web_experience_arn: ::std::option::Option<::std::string::String>,
    pub(crate) default_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::WebExperienceStatus>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) subtitle: ::std::option::Option<::std::string::String>,
    pub(crate) welcome_message: ::std::option::Option<::std::string::String>,
    pub(crate) sample_prompts_control_mode: ::std::option::Option<crate::types::WebExperienceSamplePromptsControlMode>,
    pub(crate) origins: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) identity_provider_configuration: ::std::option::Option<crate::types::IdentityProviderConfiguration>,
    pub(crate) authentication_configuration: ::std::option::Option<crate::types::WebExperienceAuthConfiguration>,
    pub(crate) error: ::std::option::Option<crate::types::ErrorDetail>,
    pub(crate) browser_extension_configuration: ::std::option::Option<crate::types::BrowserExtensionConfiguration>,
    pub(crate) customization_configuration: ::std::option::Option<crate::types::CustomizationConfiguration>,
    _request_id: Option<String>,
}
impl GetWebExperienceOutputBuilder {
    /// <p>The identifier of the Amazon Q Business application linked to the web experience.</p>
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Q Business application linked to the web experience.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The identifier of the Amazon Q Business application linked to the web experience.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The identifier of the Amazon Q Business web experience.</p>
    pub fn web_experience_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.web_experience_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Q Business web experience.</p>
    pub fn set_web_experience_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.web_experience_id = input;
        self
    }
    /// <p>The identifier of the Amazon Q Business web experience.</p>
    pub fn get_web_experience_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.web_experience_id
    }
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the Amazon Q Business web experience and required resources.</p>
    pub fn web_experience_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.web_experience_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the Amazon Q Business web experience and required resources.</p>
    pub fn set_web_experience_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.web_experience_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the Amazon Q Business web experience and required resources.</p>
    pub fn get_web_experience_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.web_experience_arn
    }
    /// <p>The endpoint of your Amazon Q Business web experience.</p>
    pub fn default_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The endpoint of your Amazon Q Business web experience.</p>
    pub fn set_default_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_endpoint = input;
        self
    }
    /// <p>The endpoint of your Amazon Q Business web experience.</p>
    pub fn get_default_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_endpoint
    }
    /// <p>The current status of the Amazon Q Business web experience. When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub fn status(mut self, input: crate::types::WebExperienceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the Amazon Q Business web experience. When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::WebExperienceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the Amazon Q Business web experience. When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::WebExperienceStatus> {
        &self.status
    }
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business web experience was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The title for your Amazon Q Business web experience.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title for your Amazon Q Business web experience.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The title for your Amazon Q Business web experience.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The subtitle for your Amazon Q Business web experience.</p>
    pub fn subtitle(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subtitle = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subtitle for your Amazon Q Business web experience.</p>
    pub fn set_subtitle(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subtitle = input;
        self
    }
    /// <p>The subtitle for your Amazon Q Business web experience.</p>
    pub fn get_subtitle(&self) -> &::std::option::Option<::std::string::String> {
        &self.subtitle
    }
    /// <p>The customized welcome message for end users of an Amazon Q Business web experience.</p>
    pub fn welcome_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.welcome_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The customized welcome message for end users of an Amazon Q Business web experience.</p>
    pub fn set_welcome_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.welcome_message = input;
        self
    }
    /// <p>The customized welcome message for end users of an Amazon Q Business web experience.</p>
    pub fn get_welcome_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.welcome_message
    }
    /// <p>Determines whether sample prompts are enabled in the web experience for an end user.</p>
    pub fn sample_prompts_control_mode(mut self, input: crate::types::WebExperienceSamplePromptsControlMode) -> Self {
        self.sample_prompts_control_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines whether sample prompts are enabled in the web experience for an end user.</p>
    pub fn set_sample_prompts_control_mode(mut self, input: ::std::option::Option<crate::types::WebExperienceSamplePromptsControlMode>) -> Self {
        self.sample_prompts_control_mode = input;
        self
    }
    /// <p>Determines whether sample prompts are enabled in the web experience for an end user.</p>
    pub fn get_sample_prompts_control_mode(&self) -> &::std::option::Option<crate::types::WebExperienceSamplePromptsControlMode> {
        &self.sample_prompts_control_mode
    }
    /// Appends an item to `origins`.
    ///
    /// To override the contents of this collection use [`set_origins`](Self::set_origins).
    ///
    /// <p>Gets the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the base URL for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p>
    pub fn origins(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.origins.unwrap_or_default();
        v.push(input.into());
        self.origins = ::std::option::Option::Some(v);
        self
    }
    /// <p>Gets the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the base URL for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p>
    pub fn set_origins(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.origins = input;
        self
    }
    /// <p>Gets the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the base URL for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p>
    pub fn get_origins(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.origins
    }
    /// <p>The Amazon Resource Name (ARN) of the service role attached to your web experience.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service role attached to your web experience.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service role attached to your web experience.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>Information about the identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
    pub fn identity_provider_configuration(mut self, input: crate::types::IdentityProviderConfiguration) -> Self {
        self.identity_provider_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
    pub fn set_identity_provider_configuration(mut self, input: ::std::option::Option<crate::types::IdentityProviderConfiguration>) -> Self {
        self.identity_provider_configuration = input;
        self
    }
    /// <p>Information about the identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
    pub fn get_identity_provider_configuration(&self) -> &::std::option::Option<crate::types::IdentityProviderConfiguration> {
        &self.identity_provider_configuration
    }
    /// <p>The authentication configuration information for your Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub fn authentication_configuration(mut self, input: crate::types::WebExperienceAuthConfiguration) -> Self {
        self.authentication_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The authentication configuration information for your Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub fn set_authentication_configuration(mut self, input: ::std::option::Option<crate::types::WebExperienceAuthConfiguration>) -> Self {
        self.authentication_configuration = input;
        self
    }
    /// <p>The authentication configuration information for your Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub fn get_authentication_configuration(&self) -> &::std::option::Option<crate::types::WebExperienceAuthConfiguration> {
        &self.authentication_configuration
    }
    /// <p>When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub fn error(mut self, input: crate::types::ErrorDetail) -> Self {
        self.error = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub fn set_error(mut self, input: ::std::option::Option<crate::types::ErrorDetail>) -> Self {
        self.error = input;
        self
    }
    /// <p>When the <code>Status</code> field value is <code>FAILED</code>, the <code>ErrorMessage</code> field contains a description of the error that caused the data source connector to fail.</p>
    pub fn get_error(&self) -> &::std::option::Option<crate::types::ErrorDetail> {
        &self.error
    }
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p>
    pub fn browser_extension_configuration(mut self, input: crate::types::BrowserExtensionConfiguration) -> Self {
        self.browser_extension_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p>
    pub fn set_browser_extension_configuration(mut self, input: ::std::option::Option<crate::types::BrowserExtensionConfiguration>) -> Self {
        self.browser_extension_configuration = input;
        self
    }
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p>
    pub fn get_browser_extension_configuration(&self) -> &::std::option::Option<crate::types::BrowserExtensionConfiguration> {
        &self.browser_extension_configuration
    }
    /// <p>Gets the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub fn customization_configuration(mut self, input: crate::types::CustomizationConfiguration) -> Self {
        self.customization_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Gets the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub fn set_customization_configuration(mut self, input: ::std::option::Option<crate::types::CustomizationConfiguration>) -> Self {
        self.customization_configuration = input;
        self
    }
    /// <p>Gets the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub fn get_customization_configuration(&self) -> &::std::option::Option<crate::types::CustomizationConfiguration> {
        &self.customization_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetWebExperienceOutput`](crate::operation::get_web_experience::GetWebExperienceOutput).
    pub fn build(self) -> crate::operation::get_web_experience::GetWebExperienceOutput {
        crate::operation::get_web_experience::GetWebExperienceOutput {
            application_id: self.application_id,
            web_experience_id: self.web_experience_id,
            web_experience_arn: self.web_experience_arn,
            default_endpoint: self.default_endpoint,
            status: self.status,
            created_at: self.created_at,
            updated_at: self.updated_at,
            title: self.title,
            subtitle: self.subtitle,
            welcome_message: self.welcome_message,
            sample_prompts_control_mode: self.sample_prompts_control_mode,
            origins: self.origins,
            role_arn: self.role_arn,
            identity_provider_configuration: self.identity_provider_configuration,
            authentication_configuration: self.authentication_configuration,
            error: self.error,
            browser_extension_configuration: self.browser_extension_configuration,
            customization_configuration: self.customization_configuration,
            _request_id: self._request_id,
        }
    }
}
