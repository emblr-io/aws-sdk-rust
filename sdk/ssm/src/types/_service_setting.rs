// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The service setting data structure.</p>
/// <p><code>ServiceSetting</code> is an account-level setting for an Amazon Web Services service. This setting defines how a user interacts with or uses a service or a feature of a service. For example, if an Amazon Web Services service charges money to the account based on feature or service usage, then the Amazon Web Services service team might create a default setting of "false". This means the user can't use this feature unless they change the setting to "true" and intentionally opt in for a paid feature.</p>
/// <p>Services map a <code>SettingId</code> object to a setting value. Amazon Web Services services teams define the default value for a <code>SettingId</code>. You can't create a new <code>SettingId</code>, but you can overwrite the default value if you have the <code>ssm:UpdateServiceSetting</code> permission for the setting. Use the <code>UpdateServiceSetting</code> API operation to change the default setting. Or, use the <code>ResetServiceSetting</code> to change the value back to the original value defined by the Amazon Web Services service team.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceSetting {
    /// <p>The ID of the service setting.</p>
    pub setting_id: ::std::option::Option<::std::string::String>,
    /// <p>The value of the service setting.</p>
    pub setting_value: ::std::option::Option<::std::string::String>,
    /// <p>The last time the service setting was modified.</p>
    pub last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The ARN of the last modified user. This field is populated only if the setting value was overwritten.</p>
    pub last_modified_user: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the service setting.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The status of the service setting. The value can be Default, Customized or PendingUpdate.</p>
    /// <ul>
    /// <li>
    /// <p>Default: The current setting uses a default value provisioned by the Amazon Web Services service team.</p></li>
    /// <li>
    /// <p>Customized: The current setting use a custom value specified by the customer.</p></li>
    /// <li>
    /// <p>PendingUpdate: The current setting uses a default or custom value, but a setting change request is pending approval.</p></li>
    /// </ul>
    pub status: ::std::option::Option<::std::string::String>,
}
impl ServiceSetting {
    /// <p>The ID of the service setting.</p>
    pub fn setting_id(&self) -> ::std::option::Option<&str> {
        self.setting_id.as_deref()
    }
    /// <p>The value of the service setting.</p>
    pub fn setting_value(&self) -> ::std::option::Option<&str> {
        self.setting_value.as_deref()
    }
    /// <p>The last time the service setting was modified.</p>
    pub fn last_modified_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_date.as_ref()
    }
    /// <p>The ARN of the last modified user. This field is populated only if the setting value was overwritten.</p>
    pub fn last_modified_user(&self) -> ::std::option::Option<&str> {
        self.last_modified_user.as_deref()
    }
    /// <p>The ARN of the service setting.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The status of the service setting. The value can be Default, Customized or PendingUpdate.</p>
    /// <ul>
    /// <li>
    /// <p>Default: The current setting uses a default value provisioned by the Amazon Web Services service team.</p></li>
    /// <li>
    /// <p>Customized: The current setting use a custom value specified by the customer.</p></li>
    /// <li>
    /// <p>PendingUpdate: The current setting uses a default or custom value, but a setting change request is pending approval.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
}
impl ServiceSetting {
    /// Creates a new builder-style object to manufacture [`ServiceSetting`](crate::types::ServiceSetting).
    pub fn builder() -> crate::types::builders::ServiceSettingBuilder {
        crate::types::builders::ServiceSettingBuilder::default()
    }
}

/// A builder for [`ServiceSetting`](crate::types::ServiceSetting).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceSettingBuilder {
    pub(crate) setting_id: ::std::option::Option<::std::string::String>,
    pub(crate) setting_value: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_user: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
}
impl ServiceSettingBuilder {
    /// <p>The ID of the service setting.</p>
    pub fn setting_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.setting_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the service setting.</p>
    pub fn set_setting_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.setting_id = input;
        self
    }
    /// <p>The ID of the service setting.</p>
    pub fn get_setting_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.setting_id
    }
    /// <p>The value of the service setting.</p>
    pub fn setting_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.setting_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the service setting.</p>
    pub fn set_setting_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.setting_value = input;
        self
    }
    /// <p>The value of the service setting.</p>
    pub fn get_setting_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.setting_value
    }
    /// <p>The last time the service setting was modified.</p>
    pub fn last_modified_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time the service setting was modified.</p>
    pub fn set_last_modified_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_date = input;
        self
    }
    /// <p>The last time the service setting was modified.</p>
    pub fn get_last_modified_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_date
    }
    /// <p>The ARN of the last modified user. This field is populated only if the setting value was overwritten.</p>
    pub fn last_modified_user(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified_user = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the last modified user. This field is populated only if the setting value was overwritten.</p>
    pub fn set_last_modified_user(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified_user = input;
        self
    }
    /// <p>The ARN of the last modified user. This field is populated only if the setting value was overwritten.</p>
    pub fn get_last_modified_user(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified_user
    }
    /// <p>The ARN of the service setting.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the service setting.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the service setting.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The status of the service setting. The value can be Default, Customized or PendingUpdate.</p>
    /// <ul>
    /// <li>
    /// <p>Default: The current setting uses a default value provisioned by the Amazon Web Services service team.</p></li>
    /// <li>
    /// <p>Customized: The current setting use a custom value specified by the customer.</p></li>
    /// <li>
    /// <p>PendingUpdate: The current setting uses a default or custom value, but a setting change request is pending approval.</p></li>
    /// </ul>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the service setting. The value can be Default, Customized or PendingUpdate.</p>
    /// <ul>
    /// <li>
    /// <p>Default: The current setting uses a default value provisioned by the Amazon Web Services service team.</p></li>
    /// <li>
    /// <p>Customized: The current setting use a custom value specified by the customer.</p></li>
    /// <li>
    /// <p>PendingUpdate: The current setting uses a default or custom value, but a setting change request is pending approval.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the service setting. The value can be Default, Customized or PendingUpdate.</p>
    /// <ul>
    /// <li>
    /// <p>Default: The current setting uses a default value provisioned by the Amazon Web Services service team.</p></li>
    /// <li>
    /// <p>Customized: The current setting use a custom value specified by the customer.</p></li>
    /// <li>
    /// <p>PendingUpdate: The current setting uses a default or custom value, but a setting change request is pending approval.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// Consumes the builder and constructs a [`ServiceSetting`](crate::types::ServiceSetting).
    pub fn build(self) -> crate::types::ServiceSetting {
        crate::types::ServiceSetting {
            setting_id: self.setting_id,
            setting_value: self.setting_value,
            last_modified_date: self.last_modified_date,
            last_modified_user: self.last_modified_user,
            arn: self.arn,
            status: self.status,
        }
    }
}
