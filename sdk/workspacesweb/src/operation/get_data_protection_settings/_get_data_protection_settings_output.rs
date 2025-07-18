// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDataProtectionSettingsOutput {
    /// <p>The data protection settings.</p>
    pub data_protection_settings: ::std::option::Option<crate::types::DataProtectionSettings>,
    _request_id: Option<String>,
}
impl GetDataProtectionSettingsOutput {
    /// <p>The data protection settings.</p>
    pub fn data_protection_settings(&self) -> ::std::option::Option<&crate::types::DataProtectionSettings> {
        self.data_protection_settings.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetDataProtectionSettingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDataProtectionSettingsOutput {
    /// Creates a new builder-style object to manufacture [`GetDataProtectionSettingsOutput`](crate::operation::get_data_protection_settings::GetDataProtectionSettingsOutput).
    pub fn builder() -> crate::operation::get_data_protection_settings::builders::GetDataProtectionSettingsOutputBuilder {
        crate::operation::get_data_protection_settings::builders::GetDataProtectionSettingsOutputBuilder::default()
    }
}

/// A builder for [`GetDataProtectionSettingsOutput`](crate::operation::get_data_protection_settings::GetDataProtectionSettingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDataProtectionSettingsOutputBuilder {
    pub(crate) data_protection_settings: ::std::option::Option<crate::types::DataProtectionSettings>,
    _request_id: Option<String>,
}
impl GetDataProtectionSettingsOutputBuilder {
    /// <p>The data protection settings.</p>
    pub fn data_protection_settings(mut self, input: crate::types::DataProtectionSettings) -> Self {
        self.data_protection_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data protection settings.</p>
    pub fn set_data_protection_settings(mut self, input: ::std::option::Option<crate::types::DataProtectionSettings>) -> Self {
        self.data_protection_settings = input;
        self
    }
    /// <p>The data protection settings.</p>
    pub fn get_data_protection_settings(&self) -> &::std::option::Option<crate::types::DataProtectionSettings> {
        &self.data_protection_settings
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDataProtectionSettingsOutput`](crate::operation::get_data_protection_settings::GetDataProtectionSettingsOutput).
    pub fn build(self) -> crate::operation::get_data_protection_settings::GetDataProtectionSettingsOutput {
        crate::operation::get_data_protection_settings::GetDataProtectionSettingsOutput {
            data_protection_settings: self.data_protection_settings,
            _request_id: self._request_id,
        }
    }
}
