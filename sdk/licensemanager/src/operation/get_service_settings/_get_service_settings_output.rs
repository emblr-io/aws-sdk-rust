// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetServiceSettingsOutput {
    /// <p>Regional S3 bucket path for storing reports, license trail event data, discovery data, and so on.</p>
    pub s3_bucket_arn: ::std::option::Option<::std::string::String>,
    /// <p>SNS topic configured to receive notifications from License Manager.</p>
    pub sns_topic_arn: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether Organizations is integrated with License Manager for cross-account discovery.</p>
    pub organization_configuration: ::std::option::Option<crate::types::OrganizationConfiguration>,
    /// <p>Indicates whether cross-account discovery is enabled.</p>
    pub enable_cross_accounts_discovery: ::std::option::Option<bool>,
    /// <p>Amazon Resource Name (ARN) of the resource share. The License Manager management account provides member accounts with access to this share.</p>
    pub license_manager_resource_share_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetServiceSettingsOutput {
    /// <p>Regional S3 bucket path for storing reports, license trail event data, discovery data, and so on.</p>
    pub fn s3_bucket_arn(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_arn.as_deref()
    }
    /// <p>SNS topic configured to receive notifications from License Manager.</p>
    pub fn sns_topic_arn(&self) -> ::std::option::Option<&str> {
        self.sns_topic_arn.as_deref()
    }
    /// <p>Indicates whether Organizations is integrated with License Manager for cross-account discovery.</p>
    pub fn organization_configuration(&self) -> ::std::option::Option<&crate::types::OrganizationConfiguration> {
        self.organization_configuration.as_ref()
    }
    /// <p>Indicates whether cross-account discovery is enabled.</p>
    pub fn enable_cross_accounts_discovery(&self) -> ::std::option::Option<bool> {
        self.enable_cross_accounts_discovery
    }
    /// <p>Amazon Resource Name (ARN) of the resource share. The License Manager management account provides member accounts with access to this share.</p>
    pub fn license_manager_resource_share_arn(&self) -> ::std::option::Option<&str> {
        self.license_manager_resource_share_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetServiceSettingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetServiceSettingsOutput {
    /// Creates a new builder-style object to manufacture [`GetServiceSettingsOutput`](crate::operation::get_service_settings::GetServiceSettingsOutput).
    pub fn builder() -> crate::operation::get_service_settings::builders::GetServiceSettingsOutputBuilder {
        crate::operation::get_service_settings::builders::GetServiceSettingsOutputBuilder::default()
    }
}

/// A builder for [`GetServiceSettingsOutput`](crate::operation::get_service_settings::GetServiceSettingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetServiceSettingsOutputBuilder {
    pub(crate) s3_bucket_arn: ::std::option::Option<::std::string::String>,
    pub(crate) sns_topic_arn: ::std::option::Option<::std::string::String>,
    pub(crate) organization_configuration: ::std::option::Option<crate::types::OrganizationConfiguration>,
    pub(crate) enable_cross_accounts_discovery: ::std::option::Option<bool>,
    pub(crate) license_manager_resource_share_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetServiceSettingsOutputBuilder {
    /// <p>Regional S3 bucket path for storing reports, license trail event data, discovery data, and so on.</p>
    pub fn s3_bucket_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Regional S3 bucket path for storing reports, license trail event data, discovery data, and so on.</p>
    pub fn set_s3_bucket_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_arn = input;
        self
    }
    /// <p>Regional S3 bucket path for storing reports, license trail event data, discovery data, and so on.</p>
    pub fn get_s3_bucket_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_arn
    }
    /// <p>SNS topic configured to receive notifications from License Manager.</p>
    pub fn sns_topic_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sns_topic_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>SNS topic configured to receive notifications from License Manager.</p>
    pub fn set_sns_topic_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sns_topic_arn = input;
        self
    }
    /// <p>SNS topic configured to receive notifications from License Manager.</p>
    pub fn get_sns_topic_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.sns_topic_arn
    }
    /// <p>Indicates whether Organizations is integrated with License Manager for cross-account discovery.</p>
    pub fn organization_configuration(mut self, input: crate::types::OrganizationConfiguration) -> Self {
        self.organization_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether Organizations is integrated with License Manager for cross-account discovery.</p>
    pub fn set_organization_configuration(mut self, input: ::std::option::Option<crate::types::OrganizationConfiguration>) -> Self {
        self.organization_configuration = input;
        self
    }
    /// <p>Indicates whether Organizations is integrated with License Manager for cross-account discovery.</p>
    pub fn get_organization_configuration(&self) -> &::std::option::Option<crate::types::OrganizationConfiguration> {
        &self.organization_configuration
    }
    /// <p>Indicates whether cross-account discovery is enabled.</p>
    pub fn enable_cross_accounts_discovery(mut self, input: bool) -> Self {
        self.enable_cross_accounts_discovery = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether cross-account discovery is enabled.</p>
    pub fn set_enable_cross_accounts_discovery(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_cross_accounts_discovery = input;
        self
    }
    /// <p>Indicates whether cross-account discovery is enabled.</p>
    pub fn get_enable_cross_accounts_discovery(&self) -> &::std::option::Option<bool> {
        &self.enable_cross_accounts_discovery
    }
    /// <p>Amazon Resource Name (ARN) of the resource share. The License Manager management account provides member accounts with access to this share.</p>
    pub fn license_manager_resource_share_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_manager_resource_share_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the resource share. The License Manager management account provides member accounts with access to this share.</p>
    pub fn set_license_manager_resource_share_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_manager_resource_share_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the resource share. The License Manager management account provides member accounts with access to this share.</p>
    pub fn get_license_manager_resource_share_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_manager_resource_share_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetServiceSettingsOutput`](crate::operation::get_service_settings::GetServiceSettingsOutput).
    pub fn build(self) -> crate::operation::get_service_settings::GetServiceSettingsOutput {
        crate::operation::get_service_settings::GetServiceSettingsOutput {
            s3_bucket_arn: self.s3_bucket_arn,
            sns_topic_arn: self.sns_topic_arn,
            organization_configuration: self.organization_configuration,
            enable_cross_accounts_discovery: self.enable_cross_accounts_discovery,
            license_manager_resource_share_arn: self.license_manager_resource_share_arn,
            _request_id: self._request_id,
        }
    }
}
