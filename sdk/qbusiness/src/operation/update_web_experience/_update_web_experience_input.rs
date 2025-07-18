// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateWebExperienceInput {
    /// <p>The identifier of the Amazon Q Business application attached to the web experience.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the Amazon Q Business web experience.</p>
    pub web_experience_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the role with permission to access the Amazon Q Business web experience and required resources.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The authentication configuration of the Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub authentication_configuration: ::std::option::Option<crate::types::WebExperienceAuthConfiguration>,
    /// <p>The title of the Amazon Q Business web experience.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>The subtitle of the Amazon Q Business web experience.</p>
    pub subtitle: ::std::option::Option<::std::string::String>,
    /// <p>A customized welcome message for an end user in an Amazon Q Business web experience.</p>
    pub welcome_message: ::std::option::Option<::std::string::String>,
    /// <p>Determines whether sample prompts are enabled in the web experience for an end user.</p>
    pub sample_prompts_control_mode: ::std::option::Option<crate::types::WebExperienceSamplePromptsControlMode>,
    /// <p>Information about the identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
    pub identity_provider_configuration: ::std::option::Option<crate::types::IdentityProviderConfiguration>,
    /// <p>Updates the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the <i>base URL</i> for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p><note>
    /// <ul>
    /// <li>
    /// <p>Any values except <code>null</code> submitted as part of this update will replace all previous values.</p></li>
    /// <li>
    /// <p>You must only submit a <i>base URL</i> and not a full path. For example, <code>https://docs.aws.amazon.com</code>.</p></li>
    /// </ul>
    /// </note>
    pub origins: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p><note>
    /// <p>For Amazon Q Business application using external OIDC-compliant identity providers (IdPs). The IdP administrator must add the browser extension sign-in redirect URLs to the IdP application. For more information, see <a href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/browser-extensions.html">Configure external OIDC identity provider for your browser extensions.</a>.</p>
    /// </note>
    pub browser_extension_configuration: ::std::option::Option<crate::types::BrowserExtensionConfiguration>,
    /// <p>Updates the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub customization_configuration: ::std::option::Option<crate::types::CustomizationConfiguration>,
}
impl UpdateWebExperienceInput {
    /// <p>The identifier of the Amazon Q Business application attached to the web experience.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The identifier of the Amazon Q Business web experience.</p>
    pub fn web_experience_id(&self) -> ::std::option::Option<&str> {
        self.web_experience_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the role with permission to access the Amazon Q Business web experience and required resources.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The authentication configuration of the Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub fn authentication_configuration(&self) -> ::std::option::Option<&crate::types::WebExperienceAuthConfiguration> {
        self.authentication_configuration.as_ref()
    }
    /// <p>The title of the Amazon Q Business web experience.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>The subtitle of the Amazon Q Business web experience.</p>
    pub fn subtitle(&self) -> ::std::option::Option<&str> {
        self.subtitle.as_deref()
    }
    /// <p>A customized welcome message for an end user in an Amazon Q Business web experience.</p>
    pub fn welcome_message(&self) -> ::std::option::Option<&str> {
        self.welcome_message.as_deref()
    }
    /// <p>Determines whether sample prompts are enabled in the web experience for an end user.</p>
    pub fn sample_prompts_control_mode(&self) -> ::std::option::Option<&crate::types::WebExperienceSamplePromptsControlMode> {
        self.sample_prompts_control_mode.as_ref()
    }
    /// <p>Information about the identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
    pub fn identity_provider_configuration(&self) -> ::std::option::Option<&crate::types::IdentityProviderConfiguration> {
        self.identity_provider_configuration.as_ref()
    }
    /// <p>Updates the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the <i>base URL</i> for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p><note>
    /// <ul>
    /// <li>
    /// <p>Any values except <code>null</code> submitted as part of this update will replace all previous values.</p></li>
    /// <li>
    /// <p>You must only submit a <i>base URL</i> and not a full path. For example, <code>https://docs.aws.amazon.com</code>.</p></li>
    /// </ul>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.origins.is_none()`.
    pub fn origins(&self) -> &[::std::string::String] {
        self.origins.as_deref().unwrap_or_default()
    }
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p><note>
    /// <p>For Amazon Q Business application using external OIDC-compliant identity providers (IdPs). The IdP administrator must add the browser extension sign-in redirect URLs to the IdP application. For more information, see <a href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/browser-extensions.html">Configure external OIDC identity provider for your browser extensions.</a>.</p>
    /// </note>
    pub fn browser_extension_configuration(&self) -> ::std::option::Option<&crate::types::BrowserExtensionConfiguration> {
        self.browser_extension_configuration.as_ref()
    }
    /// <p>Updates the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub fn customization_configuration(&self) -> ::std::option::Option<&crate::types::CustomizationConfiguration> {
        self.customization_configuration.as_ref()
    }
}
impl UpdateWebExperienceInput {
    /// Creates a new builder-style object to manufacture [`UpdateWebExperienceInput`](crate::operation::update_web_experience::UpdateWebExperienceInput).
    pub fn builder() -> crate::operation::update_web_experience::builders::UpdateWebExperienceInputBuilder {
        crate::operation::update_web_experience::builders::UpdateWebExperienceInputBuilder::default()
    }
}

/// A builder for [`UpdateWebExperienceInput`](crate::operation::update_web_experience::UpdateWebExperienceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateWebExperienceInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) web_experience_id: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) authentication_configuration: ::std::option::Option<crate::types::WebExperienceAuthConfiguration>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) subtitle: ::std::option::Option<::std::string::String>,
    pub(crate) welcome_message: ::std::option::Option<::std::string::String>,
    pub(crate) sample_prompts_control_mode: ::std::option::Option<crate::types::WebExperienceSamplePromptsControlMode>,
    pub(crate) identity_provider_configuration: ::std::option::Option<crate::types::IdentityProviderConfiguration>,
    pub(crate) origins: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) browser_extension_configuration: ::std::option::Option<crate::types::BrowserExtensionConfiguration>,
    pub(crate) customization_configuration: ::std::option::Option<crate::types::CustomizationConfiguration>,
}
impl UpdateWebExperienceInputBuilder {
    /// <p>The identifier of the Amazon Q Business application attached to the web experience.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Q Business application attached to the web experience.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The identifier of the Amazon Q Business application attached to the web experience.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The identifier of the Amazon Q Business web experience.</p>
    /// This field is required.
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
    /// <p>The Amazon Resource Name (ARN) of the role with permission to access the Amazon Q Business web experience and required resources.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role with permission to access the Amazon Q Business web experience and required resources.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role with permission to access the Amazon Q Business web experience and required resources.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The authentication configuration of the Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub fn authentication_configuration(mut self, input: crate::types::WebExperienceAuthConfiguration) -> Self {
        self.authentication_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The authentication configuration of the Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub fn set_authentication_configuration(mut self, input: ::std::option::Option<crate::types::WebExperienceAuthConfiguration>) -> Self {
        self.authentication_configuration = input;
        self
    }
    /// <p>The authentication configuration of the Amazon Q Business web experience.</p>
    #[deprecated(note = "Property associated with legacy SAML IdP flow. Deprecated in favor of using AWS IAM Identity Center for user management.")]
    pub fn get_authentication_configuration(&self) -> &::std::option::Option<crate::types::WebExperienceAuthConfiguration> {
        &self.authentication_configuration
    }
    /// <p>The title of the Amazon Q Business web experience.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title of the Amazon Q Business web experience.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The title of the Amazon Q Business web experience.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The subtitle of the Amazon Q Business web experience.</p>
    pub fn subtitle(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subtitle = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subtitle of the Amazon Q Business web experience.</p>
    pub fn set_subtitle(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subtitle = input;
        self
    }
    /// <p>The subtitle of the Amazon Q Business web experience.</p>
    pub fn get_subtitle(&self) -> &::std::option::Option<::std::string::String> {
        &self.subtitle
    }
    /// <p>A customized welcome message for an end user in an Amazon Q Business web experience.</p>
    pub fn welcome_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.welcome_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A customized welcome message for an end user in an Amazon Q Business web experience.</p>
    pub fn set_welcome_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.welcome_message = input;
        self
    }
    /// <p>A customized welcome message for an end user in an Amazon Q Business web experience.</p>
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
    /// Appends an item to `origins`.
    ///
    /// To override the contents of this collection use [`set_origins`](Self::set_origins).
    ///
    /// <p>Updates the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the <i>base URL</i> for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p><note>
    /// <ul>
    /// <li>
    /// <p>Any values except <code>null</code> submitted as part of this update will replace all previous values.</p></li>
    /// <li>
    /// <p>You must only submit a <i>base URL</i> and not a full path. For example, <code>https://docs.aws.amazon.com</code>.</p></li>
    /// </ul>
    /// </note>
    pub fn origins(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.origins.unwrap_or_default();
        v.push(input.into());
        self.origins = ::std::option::Option::Some(v);
        self
    }
    /// <p>Updates the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the <i>base URL</i> for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p><note>
    /// <ul>
    /// <li>
    /// <p>Any values except <code>null</code> submitted as part of this update will replace all previous values.</p></li>
    /// <li>
    /// <p>You must only submit a <i>base URL</i> and not a full path. For example, <code>https://docs.aws.amazon.com</code>.</p></li>
    /// </ul>
    /// </note>
    pub fn set_origins(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.origins = input;
        self
    }
    /// <p>Updates the website domain origins that are allowed to embed the Amazon Q Business web experience. The <i>domain origin</i> refers to the <i>base URL</i> for accessing a website including the protocol (<code>http/https</code>), the domain name, and the port number (if specified).</p><note>
    /// <ul>
    /// <li>
    /// <p>Any values except <code>null</code> submitted as part of this update will replace all previous values.</p></li>
    /// <li>
    /// <p>You must only submit a <i>base URL</i> and not a full path. For example, <code>https://docs.aws.amazon.com</code>.</p></li>
    /// </ul>
    /// </note>
    pub fn get_origins(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.origins
    }
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p><note>
    /// <p>For Amazon Q Business application using external OIDC-compliant identity providers (IdPs). The IdP administrator must add the browser extension sign-in redirect URLs to the IdP application. For more information, see <a href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/browser-extensions.html">Configure external OIDC identity provider for your browser extensions.</a>.</p>
    /// </note>
    pub fn browser_extension_configuration(mut self, input: crate::types::BrowserExtensionConfiguration) -> Self {
        self.browser_extension_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p><note>
    /// <p>For Amazon Q Business application using external OIDC-compliant identity providers (IdPs). The IdP administrator must add the browser extension sign-in redirect URLs to the IdP application. For more information, see <a href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/browser-extensions.html">Configure external OIDC identity provider for your browser extensions.</a>.</p>
    /// </note>
    pub fn set_browser_extension_configuration(mut self, input: ::std::option::Option<crate::types::BrowserExtensionConfiguration>) -> Self {
        self.browser_extension_configuration = input;
        self
    }
    /// <p>The browser extension configuration for an Amazon Q Business web experience.</p><note>
    /// <p>For Amazon Q Business application using external OIDC-compliant identity providers (IdPs). The IdP administrator must add the browser extension sign-in redirect URLs to the IdP application. For more information, see <a href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/browser-extensions.html">Configure external OIDC identity provider for your browser extensions.</a>.</p>
    /// </note>
    pub fn get_browser_extension_configuration(&self) -> &::std::option::Option<crate::types::BrowserExtensionConfiguration> {
        &self.browser_extension_configuration
    }
    /// <p>Updates the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub fn customization_configuration(mut self, input: crate::types::CustomizationConfiguration) -> Self {
        self.customization_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Updates the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub fn set_customization_configuration(mut self, input: ::std::option::Option<crate::types::CustomizationConfiguration>) -> Self {
        self.customization_configuration = input;
        self
    }
    /// <p>Updates the custom logo, favicon, font, and color used in the Amazon Q web experience.</p>
    pub fn get_customization_configuration(&self) -> &::std::option::Option<crate::types::CustomizationConfiguration> {
        &self.customization_configuration
    }
    /// Consumes the builder and constructs a [`UpdateWebExperienceInput`](crate::operation::update_web_experience::UpdateWebExperienceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_web_experience::UpdateWebExperienceInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_web_experience::UpdateWebExperienceInput {
            application_id: self.application_id,
            web_experience_id: self.web_experience_id,
            role_arn: self.role_arn,
            authentication_configuration: self.authentication_configuration,
            title: self.title,
            subtitle: self.subtitle,
            welcome_message: self.welcome_message,
            sample_prompts_control_mode: self.sample_prompts_control_mode,
            identity_provider_configuration: self.identity_provider_configuration,
            origins: self.origins,
            browser_extension_configuration: self.browser_extension_configuration,
            customization_configuration: self.customization_configuration,
        })
    }
}
