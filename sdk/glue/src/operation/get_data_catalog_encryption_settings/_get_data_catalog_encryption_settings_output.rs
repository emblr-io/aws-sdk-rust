// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDataCatalogEncryptionSettingsOutput {
    /// <p>The requested security configuration.</p>
    pub data_catalog_encryption_settings: ::std::option::Option<crate::types::DataCatalogEncryptionSettings>,
    _request_id: Option<String>,
}
impl GetDataCatalogEncryptionSettingsOutput {
    /// <p>The requested security configuration.</p>
    pub fn data_catalog_encryption_settings(&self) -> ::std::option::Option<&crate::types::DataCatalogEncryptionSettings> {
        self.data_catalog_encryption_settings.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetDataCatalogEncryptionSettingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDataCatalogEncryptionSettingsOutput {
    /// Creates a new builder-style object to manufacture [`GetDataCatalogEncryptionSettingsOutput`](crate::operation::get_data_catalog_encryption_settings::GetDataCatalogEncryptionSettingsOutput).
    pub fn builder() -> crate::operation::get_data_catalog_encryption_settings::builders::GetDataCatalogEncryptionSettingsOutputBuilder {
        crate::operation::get_data_catalog_encryption_settings::builders::GetDataCatalogEncryptionSettingsOutputBuilder::default()
    }
}

/// A builder for [`GetDataCatalogEncryptionSettingsOutput`](crate::operation::get_data_catalog_encryption_settings::GetDataCatalogEncryptionSettingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDataCatalogEncryptionSettingsOutputBuilder {
    pub(crate) data_catalog_encryption_settings: ::std::option::Option<crate::types::DataCatalogEncryptionSettings>,
    _request_id: Option<String>,
}
impl GetDataCatalogEncryptionSettingsOutputBuilder {
    /// <p>The requested security configuration.</p>
    pub fn data_catalog_encryption_settings(mut self, input: crate::types::DataCatalogEncryptionSettings) -> Self {
        self.data_catalog_encryption_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The requested security configuration.</p>
    pub fn set_data_catalog_encryption_settings(mut self, input: ::std::option::Option<crate::types::DataCatalogEncryptionSettings>) -> Self {
        self.data_catalog_encryption_settings = input;
        self
    }
    /// <p>The requested security configuration.</p>
    pub fn get_data_catalog_encryption_settings(&self) -> &::std::option::Option<crate::types::DataCatalogEncryptionSettings> {
        &self.data_catalog_encryption_settings
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDataCatalogEncryptionSettingsOutput`](crate::operation::get_data_catalog_encryption_settings::GetDataCatalogEncryptionSettingsOutput).
    pub fn build(self) -> crate::operation::get_data_catalog_encryption_settings::GetDataCatalogEncryptionSettingsOutput {
        crate::operation::get_data_catalog_encryption_settings::GetDataCatalogEncryptionSettingsOutput {
            data_catalog_encryption_settings: self.data_catalog_encryption_settings,
            _request_id: self._request_id,
        }
    }
}
