// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The IP access settings resource that can be associated with a web portal.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct IpAccessSettings {
    /// <p>The ARN of the IP access settings resource.</p>
    pub ip_access_settings_arn: ::std::string::String,
    /// <p>A list of web portal ARNs that this IP access settings resource is associated with.</p>
    pub associated_portal_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The IP rules of the IP access settings.</p>
    pub ip_rules: ::std::option::Option<::std::vec::Vec<crate::types::IpRule>>,
    /// <p>The display name of the IP access settings.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the IP access settings.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The creation date timestamp of the IP access settings.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The customer managed key used to encrypt sensitive information in the IP access settings.</p>
    pub customer_managed_key: ::std::option::Option<::std::string::String>,
    /// <p>The additional encryption context of the IP access settings.</p>
    pub additional_encryption_context: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl IpAccessSettings {
    /// <p>The ARN of the IP access settings resource.</p>
    pub fn ip_access_settings_arn(&self) -> &str {
        use std::ops::Deref;
        self.ip_access_settings_arn.deref()
    }
    /// <p>A list of web portal ARNs that this IP access settings resource is associated with.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.associated_portal_arns.is_none()`.
    pub fn associated_portal_arns(&self) -> &[::std::string::String] {
        self.associated_portal_arns.as_deref().unwrap_or_default()
    }
    /// <p>The IP rules of the IP access settings.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ip_rules.is_none()`.
    pub fn ip_rules(&self) -> &[crate::types::IpRule] {
        self.ip_rules.as_deref().unwrap_or_default()
    }
    /// <p>The display name of the IP access settings.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The description of the IP access settings.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The creation date timestamp of the IP access settings.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
    /// <p>The customer managed key used to encrypt sensitive information in the IP access settings.</p>
    pub fn customer_managed_key(&self) -> ::std::option::Option<&str> {
        self.customer_managed_key.as_deref()
    }
    /// <p>The additional encryption context of the IP access settings.</p>
    pub fn additional_encryption_context(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.additional_encryption_context.as_ref()
    }
}
impl ::std::fmt::Debug for IpAccessSettings {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IpAccessSettings");
        formatter.field("ip_access_settings_arn", &self.ip_access_settings_arn);
        formatter.field("associated_portal_arns", &self.associated_portal_arns);
        formatter.field("ip_rules", &"*** Sensitive Data Redacted ***");
        formatter.field("display_name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("creation_date", &self.creation_date);
        formatter.field("customer_managed_key", &self.customer_managed_key);
        formatter.field("additional_encryption_context", &self.additional_encryption_context);
        formatter.finish()
    }
}
impl IpAccessSettings {
    /// Creates a new builder-style object to manufacture [`IpAccessSettings`](crate::types::IpAccessSettings).
    pub fn builder() -> crate::types::builders::IpAccessSettingsBuilder {
        crate::types::builders::IpAccessSettingsBuilder::default()
    }
}

/// A builder for [`IpAccessSettings`](crate::types::IpAccessSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct IpAccessSettingsBuilder {
    pub(crate) ip_access_settings_arn: ::std::option::Option<::std::string::String>,
    pub(crate) associated_portal_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) ip_rules: ::std::option::Option<::std::vec::Vec<crate::types::IpRule>>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) customer_managed_key: ::std::option::Option<::std::string::String>,
    pub(crate) additional_encryption_context: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl IpAccessSettingsBuilder {
    /// <p>The ARN of the IP access settings resource.</p>
    /// This field is required.
    pub fn ip_access_settings_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip_access_settings_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IP access settings resource.</p>
    pub fn set_ip_access_settings_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip_access_settings_arn = input;
        self
    }
    /// <p>The ARN of the IP access settings resource.</p>
    pub fn get_ip_access_settings_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip_access_settings_arn
    }
    /// Appends an item to `associated_portal_arns`.
    ///
    /// To override the contents of this collection use [`set_associated_portal_arns`](Self::set_associated_portal_arns).
    ///
    /// <p>A list of web portal ARNs that this IP access settings resource is associated with.</p>
    pub fn associated_portal_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.associated_portal_arns.unwrap_or_default();
        v.push(input.into());
        self.associated_portal_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of web portal ARNs that this IP access settings resource is associated with.</p>
    pub fn set_associated_portal_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.associated_portal_arns = input;
        self
    }
    /// <p>A list of web portal ARNs that this IP access settings resource is associated with.</p>
    pub fn get_associated_portal_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.associated_portal_arns
    }
    /// Appends an item to `ip_rules`.
    ///
    /// To override the contents of this collection use [`set_ip_rules`](Self::set_ip_rules).
    ///
    /// <p>The IP rules of the IP access settings.</p>
    pub fn ip_rules(mut self, input: crate::types::IpRule) -> Self {
        let mut v = self.ip_rules.unwrap_or_default();
        v.push(input);
        self.ip_rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IP rules of the IP access settings.</p>
    pub fn set_ip_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IpRule>>) -> Self {
        self.ip_rules = input;
        self
    }
    /// <p>The IP rules of the IP access settings.</p>
    pub fn get_ip_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IpRule>> {
        &self.ip_rules
    }
    /// <p>The display name of the IP access settings.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the IP access settings.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The display name of the IP access settings.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The description of the IP access settings.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the IP access settings.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the IP access settings.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The creation date timestamp of the IP access settings.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation date timestamp of the IP access settings.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The creation date timestamp of the IP access settings.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// <p>The customer managed key used to encrypt sensitive information in the IP access settings.</p>
    pub fn customer_managed_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.customer_managed_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The customer managed key used to encrypt sensitive information in the IP access settings.</p>
    pub fn set_customer_managed_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.customer_managed_key = input;
        self
    }
    /// <p>The customer managed key used to encrypt sensitive information in the IP access settings.</p>
    pub fn get_customer_managed_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.customer_managed_key
    }
    /// Adds a key-value pair to `additional_encryption_context`.
    ///
    /// To override the contents of this collection use [`set_additional_encryption_context`](Self::set_additional_encryption_context).
    ///
    /// <p>The additional encryption context of the IP access settings.</p>
    pub fn additional_encryption_context(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.additional_encryption_context.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.additional_encryption_context = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The additional encryption context of the IP access settings.</p>
    pub fn set_additional_encryption_context(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.additional_encryption_context = input;
        self
    }
    /// <p>The additional encryption context of the IP access settings.</p>
    pub fn get_additional_encryption_context(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.additional_encryption_context
    }
    /// Consumes the builder and constructs a [`IpAccessSettings`](crate::types::IpAccessSettings).
    /// This method will fail if any of the following fields are not set:
    /// - [`ip_access_settings_arn`](crate::types::builders::IpAccessSettingsBuilder::ip_access_settings_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::IpAccessSettings, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IpAccessSettings {
            ip_access_settings_arn: self.ip_access_settings_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ip_access_settings_arn",
                    "ip_access_settings_arn was not specified but it is required when building IpAccessSettings",
                )
            })?,
            associated_portal_arns: self.associated_portal_arns,
            ip_rules: self.ip_rules,
            display_name: self.display_name,
            description: self.description,
            creation_date: self.creation_date,
            customer_managed_key: self.customer_managed_key,
            additional_encryption_context: self.additional_encryption_context,
        })
    }
}
impl ::std::fmt::Debug for IpAccessSettingsBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IpAccessSettingsBuilder");
        formatter.field("ip_access_settings_arn", &self.ip_access_settings_arn);
        formatter.field("associated_portal_arns", &self.associated_portal_arns);
        formatter.field("ip_rules", &"*** Sensitive Data Redacted ***");
        formatter.field("display_name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("creation_date", &self.creation_date);
        formatter.field("customer_managed_key", &self.customer_managed_key);
        formatter.field("additional_encryption_context", &self.additional_encryption_context);
        formatter.finish()
    }
}
