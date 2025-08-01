// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SetUserMfaPreferenceInput {
    /// <p>User preferences for SMS message MFA. Activates or deactivates SMS MFA and sets it as the preferred MFA method when multiple methods are available.</p>
    pub sms_mfa_settings: ::std::option::Option<crate::types::SmsMfaSettingsType>,
    /// <p>User preferences for time-based one-time password (TOTP) MFA. Activates or deactivates TOTP MFA and sets it as the preferred MFA method when multiple methods are available. Users must register a TOTP authenticator before they set this as their preferred MFA method.</p>
    pub software_token_mfa_settings: ::std::option::Option<crate::types::SoftwareTokenMfaSettingsType>,
    /// <p>User preferences for email message MFA. Activates or deactivates email MFA and sets it as the preferred MFA method when multiple methods are available. To activate this setting, your user pool must be in the <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/feature-plans-features-essentials.html"> Essentials tier</a> or higher.</p>
    pub email_mfa_settings: ::std::option::Option<crate::types::EmailMfaSettingsType>,
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub access_token: ::std::option::Option<::std::string::String>,
}
impl SetUserMfaPreferenceInput {
    /// <p>User preferences for SMS message MFA. Activates or deactivates SMS MFA and sets it as the preferred MFA method when multiple methods are available.</p>
    pub fn sms_mfa_settings(&self) -> ::std::option::Option<&crate::types::SmsMfaSettingsType> {
        self.sms_mfa_settings.as_ref()
    }
    /// <p>User preferences for time-based one-time password (TOTP) MFA. Activates or deactivates TOTP MFA and sets it as the preferred MFA method when multiple methods are available. Users must register a TOTP authenticator before they set this as their preferred MFA method.</p>
    pub fn software_token_mfa_settings(&self) -> ::std::option::Option<&crate::types::SoftwareTokenMfaSettingsType> {
        self.software_token_mfa_settings.as_ref()
    }
    /// <p>User preferences for email message MFA. Activates or deactivates email MFA and sets it as the preferred MFA method when multiple methods are available. To activate this setting, your user pool must be in the <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/feature-plans-features-essentials.html"> Essentials tier</a> or higher.</p>
    pub fn email_mfa_settings(&self) -> ::std::option::Option<&crate::types::EmailMfaSettingsType> {
        self.email_mfa_settings.as_ref()
    }
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub fn access_token(&self) -> ::std::option::Option<&str> {
        self.access_token.as_deref()
    }
}
impl ::std::fmt::Debug for SetUserMfaPreferenceInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SetUserMfaPreferenceInput");
        formatter.field("sms_mfa_settings", &self.sms_mfa_settings);
        formatter.field("software_token_mfa_settings", &self.software_token_mfa_settings);
        formatter.field("email_mfa_settings", &self.email_mfa_settings);
        formatter.field("access_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl SetUserMfaPreferenceInput {
    /// Creates a new builder-style object to manufacture [`SetUserMfaPreferenceInput`](crate::operation::set_user_mfa_preference::SetUserMfaPreferenceInput).
    pub fn builder() -> crate::operation::set_user_mfa_preference::builders::SetUserMfaPreferenceInputBuilder {
        crate::operation::set_user_mfa_preference::builders::SetUserMfaPreferenceInputBuilder::default()
    }
}

/// A builder for [`SetUserMfaPreferenceInput`](crate::operation::set_user_mfa_preference::SetUserMfaPreferenceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SetUserMfaPreferenceInputBuilder {
    pub(crate) sms_mfa_settings: ::std::option::Option<crate::types::SmsMfaSettingsType>,
    pub(crate) software_token_mfa_settings: ::std::option::Option<crate::types::SoftwareTokenMfaSettingsType>,
    pub(crate) email_mfa_settings: ::std::option::Option<crate::types::EmailMfaSettingsType>,
    pub(crate) access_token: ::std::option::Option<::std::string::String>,
}
impl SetUserMfaPreferenceInputBuilder {
    /// <p>User preferences for SMS message MFA. Activates or deactivates SMS MFA and sets it as the preferred MFA method when multiple methods are available.</p>
    pub fn sms_mfa_settings(mut self, input: crate::types::SmsMfaSettingsType) -> Self {
        self.sms_mfa_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>User preferences for SMS message MFA. Activates or deactivates SMS MFA and sets it as the preferred MFA method when multiple methods are available.</p>
    pub fn set_sms_mfa_settings(mut self, input: ::std::option::Option<crate::types::SmsMfaSettingsType>) -> Self {
        self.sms_mfa_settings = input;
        self
    }
    /// <p>User preferences for SMS message MFA. Activates or deactivates SMS MFA and sets it as the preferred MFA method when multiple methods are available.</p>
    pub fn get_sms_mfa_settings(&self) -> &::std::option::Option<crate::types::SmsMfaSettingsType> {
        &self.sms_mfa_settings
    }
    /// <p>User preferences for time-based one-time password (TOTP) MFA. Activates or deactivates TOTP MFA and sets it as the preferred MFA method when multiple methods are available. Users must register a TOTP authenticator before they set this as their preferred MFA method.</p>
    pub fn software_token_mfa_settings(mut self, input: crate::types::SoftwareTokenMfaSettingsType) -> Self {
        self.software_token_mfa_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>User preferences for time-based one-time password (TOTP) MFA. Activates or deactivates TOTP MFA and sets it as the preferred MFA method when multiple methods are available. Users must register a TOTP authenticator before they set this as their preferred MFA method.</p>
    pub fn set_software_token_mfa_settings(mut self, input: ::std::option::Option<crate::types::SoftwareTokenMfaSettingsType>) -> Self {
        self.software_token_mfa_settings = input;
        self
    }
    /// <p>User preferences for time-based one-time password (TOTP) MFA. Activates or deactivates TOTP MFA and sets it as the preferred MFA method when multiple methods are available. Users must register a TOTP authenticator before they set this as their preferred MFA method.</p>
    pub fn get_software_token_mfa_settings(&self) -> &::std::option::Option<crate::types::SoftwareTokenMfaSettingsType> {
        &self.software_token_mfa_settings
    }
    /// <p>User preferences for email message MFA. Activates or deactivates email MFA and sets it as the preferred MFA method when multiple methods are available. To activate this setting, your user pool must be in the <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/feature-plans-features-essentials.html"> Essentials tier</a> or higher.</p>
    pub fn email_mfa_settings(mut self, input: crate::types::EmailMfaSettingsType) -> Self {
        self.email_mfa_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>User preferences for email message MFA. Activates or deactivates email MFA and sets it as the preferred MFA method when multiple methods are available. To activate this setting, your user pool must be in the <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/feature-plans-features-essentials.html"> Essentials tier</a> or higher.</p>
    pub fn set_email_mfa_settings(mut self, input: ::std::option::Option<crate::types::EmailMfaSettingsType>) -> Self {
        self.email_mfa_settings = input;
        self
    }
    /// <p>User preferences for email message MFA. Activates or deactivates email MFA and sets it as the preferred MFA method when multiple methods are available. To activate this setting, your user pool must be in the <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/feature-plans-features-essentials.html"> Essentials tier</a> or higher.</p>
    pub fn get_email_mfa_settings(&self) -> &::std::option::Option<crate::types::EmailMfaSettingsType> {
        &self.email_mfa_settings
    }
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    /// This field is required.
    pub fn access_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub fn set_access_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_token = input;
        self
    }
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub fn get_access_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_token
    }
    /// Consumes the builder and constructs a [`SetUserMfaPreferenceInput`](crate::operation::set_user_mfa_preference::SetUserMfaPreferenceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::set_user_mfa_preference::SetUserMfaPreferenceInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::set_user_mfa_preference::SetUserMfaPreferenceInput {
            sms_mfa_settings: self.sms_mfa_settings,
            software_token_mfa_settings: self.software_token_mfa_settings,
            email_mfa_settings: self.email_mfa_settings,
            access_token: self.access_token,
        })
    }
}
impl ::std::fmt::Debug for SetUserMfaPreferenceInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SetUserMfaPreferenceInputBuilder");
        formatter.field("sms_mfa_settings", &self.sms_mfa_settings);
        formatter.field("software_token_mfa_settings", &self.software_token_mfa_settings);
        formatter.field("email_mfa_settings", &self.email_mfa_settings);
        formatter.field("access_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
