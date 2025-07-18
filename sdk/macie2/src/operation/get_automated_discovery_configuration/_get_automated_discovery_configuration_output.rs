// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAutomatedDiscoveryConfigurationOutput {
    /// <p>Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization. Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for new member accounts; and, NONE, don't enable it for any accounts.</p>
    pub auto_enable_organization_members: ::std::option::Option<crate::types::AutoEnableMode>,
    /// <p>The unique identifier for the classification scope that's used when performing automated sensitive data discovery. The classification scope specifies S3 buckets to exclude from analyses.</p>
    pub classification_scope_id: ::std::option::Option<::std::string::String>,
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most recently disabled. This value is null if automated sensitive data discovery is currently enabled.</p>
    pub disabled_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was initially enabled. This value is null if automated sensitive data discovery has never been enabled.</p>
    pub first_enabled_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of automated sensitive data discovery was most recently changed.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The unique identifier for the sensitivity inspection template that's used when performing automated sensitive data discovery. The template specifies which allow lists, custom data identifiers, and managed data identifiers to use when analyzing data.</p>
    pub sensitivity_inspection_template_id: ::std::option::Option<::std::string::String>,
    /// <p>The current status of automated sensitive data discovery for the organization or account. Possible values are: ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED, don't perform automated sensitive data discovery activities.</p>
    pub status: ::std::option::Option<crate::types::AutomatedDiscoveryStatus>,
    _request_id: Option<String>,
}
impl GetAutomatedDiscoveryConfigurationOutput {
    /// <p>Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization. Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for new member accounts; and, NONE, don't enable it for any accounts.</p>
    pub fn auto_enable_organization_members(&self) -> ::std::option::Option<&crate::types::AutoEnableMode> {
        self.auto_enable_organization_members.as_ref()
    }
    /// <p>The unique identifier for the classification scope that's used when performing automated sensitive data discovery. The classification scope specifies S3 buckets to exclude from analyses.</p>
    pub fn classification_scope_id(&self) -> ::std::option::Option<&str> {
        self.classification_scope_id.as_deref()
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most recently disabled. This value is null if automated sensitive data discovery is currently enabled.</p>
    pub fn disabled_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.disabled_at.as_ref()
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was initially enabled. This value is null if automated sensitive data discovery has never been enabled.</p>
    pub fn first_enabled_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.first_enabled_at.as_ref()
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of automated sensitive data discovery was most recently changed.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>The unique identifier for the sensitivity inspection template that's used when performing automated sensitive data discovery. The template specifies which allow lists, custom data identifiers, and managed data identifiers to use when analyzing data.</p>
    pub fn sensitivity_inspection_template_id(&self) -> ::std::option::Option<&str> {
        self.sensitivity_inspection_template_id.as_deref()
    }
    /// <p>The current status of automated sensitive data discovery for the organization or account. Possible values are: ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED, don't perform automated sensitive data discovery activities.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::AutomatedDiscoveryStatus> {
        self.status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetAutomatedDiscoveryConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAutomatedDiscoveryConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`GetAutomatedDiscoveryConfigurationOutput`](crate::operation::get_automated_discovery_configuration::GetAutomatedDiscoveryConfigurationOutput).
    pub fn builder() -> crate::operation::get_automated_discovery_configuration::builders::GetAutomatedDiscoveryConfigurationOutputBuilder {
        crate::operation::get_automated_discovery_configuration::builders::GetAutomatedDiscoveryConfigurationOutputBuilder::default()
    }
}

/// A builder for [`GetAutomatedDiscoveryConfigurationOutput`](crate::operation::get_automated_discovery_configuration::GetAutomatedDiscoveryConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAutomatedDiscoveryConfigurationOutputBuilder {
    pub(crate) auto_enable_organization_members: ::std::option::Option<crate::types::AutoEnableMode>,
    pub(crate) classification_scope_id: ::std::option::Option<::std::string::String>,
    pub(crate) disabled_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) first_enabled_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) sensitivity_inspection_template_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::AutomatedDiscoveryStatus>,
    _request_id: Option<String>,
}
impl GetAutomatedDiscoveryConfigurationOutputBuilder {
    /// <p>Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization. Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for new member accounts; and, NONE, don't enable it for any accounts.</p>
    pub fn auto_enable_organization_members(mut self, input: crate::types::AutoEnableMode) -> Self {
        self.auto_enable_organization_members = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization. Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for new member accounts; and, NONE, don't enable it for any accounts.</p>
    pub fn set_auto_enable_organization_members(mut self, input: ::std::option::Option<crate::types::AutoEnableMode>) -> Self {
        self.auto_enable_organization_members = input;
        self
    }
    /// <p>Specifies whether automated sensitive data discovery is enabled automatically for accounts in the organization. Possible values are: ALL, enable it for all existing accounts and new member accounts; NEW, enable it only for new member accounts; and, NONE, don't enable it for any accounts.</p>
    pub fn get_auto_enable_organization_members(&self) -> &::std::option::Option<crate::types::AutoEnableMode> {
        &self.auto_enable_organization_members
    }
    /// <p>The unique identifier for the classification scope that's used when performing automated sensitive data discovery. The classification scope specifies S3 buckets to exclude from analyses.</p>
    pub fn classification_scope_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.classification_scope_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the classification scope that's used when performing automated sensitive data discovery. The classification scope specifies S3 buckets to exclude from analyses.</p>
    pub fn set_classification_scope_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.classification_scope_id = input;
        self
    }
    /// <p>The unique identifier for the classification scope that's used when performing automated sensitive data discovery. The classification scope specifies S3 buckets to exclude from analyses.</p>
    pub fn get_classification_scope_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.classification_scope_id
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most recently disabled. This value is null if automated sensitive data discovery is currently enabled.</p>
    pub fn disabled_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.disabled_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most recently disabled. This value is null if automated sensitive data discovery is currently enabled.</p>
    pub fn set_disabled_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.disabled_at = input;
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was most recently disabled. This value is null if automated sensitive data discovery is currently enabled.</p>
    pub fn get_disabled_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.disabled_at
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was initially enabled. This value is null if automated sensitive data discovery has never been enabled.</p>
    pub fn first_enabled_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.first_enabled_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was initially enabled. This value is null if automated sensitive data discovery has never been enabled.</p>
    pub fn set_first_enabled_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.first_enabled_at = input;
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when automated sensitive data discovery was initially enabled. This value is null if automated sensitive data discovery has never been enabled.</p>
    pub fn get_first_enabled_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.first_enabled_at
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of automated sensitive data discovery was most recently changed.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of automated sensitive data discovery was most recently changed.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the configuration settings or status of automated sensitive data discovery was most recently changed.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// <p>The unique identifier for the sensitivity inspection template that's used when performing automated sensitive data discovery. The template specifies which allow lists, custom data identifiers, and managed data identifiers to use when analyzing data.</p>
    pub fn sensitivity_inspection_template_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sensitivity_inspection_template_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the sensitivity inspection template that's used when performing automated sensitive data discovery. The template specifies which allow lists, custom data identifiers, and managed data identifiers to use when analyzing data.</p>
    pub fn set_sensitivity_inspection_template_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sensitivity_inspection_template_id = input;
        self
    }
    /// <p>The unique identifier for the sensitivity inspection template that's used when performing automated sensitive data discovery. The template specifies which allow lists, custom data identifiers, and managed data identifiers to use when analyzing data.</p>
    pub fn get_sensitivity_inspection_template_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.sensitivity_inspection_template_id
    }
    /// <p>The current status of automated sensitive data discovery for the organization or account. Possible values are: ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED, don't perform automated sensitive data discovery activities.</p>
    pub fn status(mut self, input: crate::types::AutomatedDiscoveryStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of automated sensitive data discovery for the organization or account. Possible values are: ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED, don't perform automated sensitive data discovery activities.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AutomatedDiscoveryStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of automated sensitive data discovery for the organization or account. Possible values are: ENABLED, use the specified settings to perform automated sensitive data discovery activities; and, DISABLED, don't perform automated sensitive data discovery activities.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AutomatedDiscoveryStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAutomatedDiscoveryConfigurationOutput`](crate::operation::get_automated_discovery_configuration::GetAutomatedDiscoveryConfigurationOutput).
    pub fn build(self) -> crate::operation::get_automated_discovery_configuration::GetAutomatedDiscoveryConfigurationOutput {
        crate::operation::get_automated_discovery_configuration::GetAutomatedDiscoveryConfigurationOutput {
            auto_enable_organization_members: self.auto_enable_organization_members,
            classification_scope_id: self.classification_scope_id,
            disabled_at: self.disabled_at,
            first_enabled_at: self.first_enabled_at,
            last_updated_at: self.last_updated_at,
            sensitivity_inspection_template_id: self.sensitivity_inspection_template_id,
            status: self.status,
            _request_id: self._request_id,
        }
    }
}
