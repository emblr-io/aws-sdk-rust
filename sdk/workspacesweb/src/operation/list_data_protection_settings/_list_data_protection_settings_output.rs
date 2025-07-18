// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDataProtectionSettingsOutput {
    /// <p>The data protection settings.</p>
    pub data_protection_settings: ::std::option::Option<::std::vec::Vec<crate::types::DataProtectionSettingsSummary>>,
    /// <p>The pagination token used to retrieve the next page of results for this operation.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDataProtectionSettingsOutput {
    /// <p>The data protection settings.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_protection_settings.is_none()`.
    pub fn data_protection_settings(&self) -> &[crate::types::DataProtectionSettingsSummary] {
        self.data_protection_settings.as_deref().unwrap_or_default()
    }
    /// <p>The pagination token used to retrieve the next page of results for this operation.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDataProtectionSettingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDataProtectionSettingsOutput {
    /// Creates a new builder-style object to manufacture [`ListDataProtectionSettingsOutput`](crate::operation::list_data_protection_settings::ListDataProtectionSettingsOutput).
    pub fn builder() -> crate::operation::list_data_protection_settings::builders::ListDataProtectionSettingsOutputBuilder {
        crate::operation::list_data_protection_settings::builders::ListDataProtectionSettingsOutputBuilder::default()
    }
}

/// A builder for [`ListDataProtectionSettingsOutput`](crate::operation::list_data_protection_settings::ListDataProtectionSettingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDataProtectionSettingsOutputBuilder {
    pub(crate) data_protection_settings: ::std::option::Option<::std::vec::Vec<crate::types::DataProtectionSettingsSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDataProtectionSettingsOutputBuilder {
    /// Appends an item to `data_protection_settings`.
    ///
    /// To override the contents of this collection use [`set_data_protection_settings`](Self::set_data_protection_settings).
    ///
    /// <p>The data protection settings.</p>
    pub fn data_protection_settings(mut self, input: crate::types::DataProtectionSettingsSummary) -> Self {
        let mut v = self.data_protection_settings.unwrap_or_default();
        v.push(input);
        self.data_protection_settings = ::std::option::Option::Some(v);
        self
    }
    /// <p>The data protection settings.</p>
    pub fn set_data_protection_settings(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::DataProtectionSettingsSummary>>,
    ) -> Self {
        self.data_protection_settings = input;
        self
    }
    /// <p>The data protection settings.</p>
    pub fn get_data_protection_settings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataProtectionSettingsSummary>> {
        &self.data_protection_settings
    }
    /// <p>The pagination token used to retrieve the next page of results for this operation.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token used to retrieve the next page of results for this operation.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token used to retrieve the next page of results for this operation.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListDataProtectionSettingsOutput`](crate::operation::list_data_protection_settings::ListDataProtectionSettingsOutput).
    pub fn build(self) -> crate::operation::list_data_protection_settings::ListDataProtectionSettingsOutput {
        crate::operation::list_data_protection_settings::ListDataProtectionSettingsOutput {
            data_protection_settings: self.data_protection_settings,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
