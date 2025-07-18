// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListNetworkSettingsOutput {
    /// <p>The network settings.</p>
    pub network_settings: ::std::option::Option<::std::vec::Vec<crate::types::NetworkSettingsSummary>>,
    /// <p>The pagination token used to retrieve the next page of results for this operation.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListNetworkSettingsOutput {
    /// <p>The network settings.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.network_settings.is_none()`.
    pub fn network_settings(&self) -> &[crate::types::NetworkSettingsSummary] {
        self.network_settings.as_deref().unwrap_or_default()
    }
    /// <p>The pagination token used to retrieve the next page of results for this operation.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListNetworkSettingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListNetworkSettingsOutput {
    /// Creates a new builder-style object to manufacture [`ListNetworkSettingsOutput`](crate::operation::list_network_settings::ListNetworkSettingsOutput).
    pub fn builder() -> crate::operation::list_network_settings::builders::ListNetworkSettingsOutputBuilder {
        crate::operation::list_network_settings::builders::ListNetworkSettingsOutputBuilder::default()
    }
}

/// A builder for [`ListNetworkSettingsOutput`](crate::operation::list_network_settings::ListNetworkSettingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListNetworkSettingsOutputBuilder {
    pub(crate) network_settings: ::std::option::Option<::std::vec::Vec<crate::types::NetworkSettingsSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListNetworkSettingsOutputBuilder {
    /// Appends an item to `network_settings`.
    ///
    /// To override the contents of this collection use [`set_network_settings`](Self::set_network_settings).
    ///
    /// <p>The network settings.</p>
    pub fn network_settings(mut self, input: crate::types::NetworkSettingsSummary) -> Self {
        let mut v = self.network_settings.unwrap_or_default();
        v.push(input);
        self.network_settings = ::std::option::Option::Some(v);
        self
    }
    /// <p>The network settings.</p>
    pub fn set_network_settings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NetworkSettingsSummary>>) -> Self {
        self.network_settings = input;
        self
    }
    /// <p>The network settings.</p>
    pub fn get_network_settings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NetworkSettingsSummary>> {
        &self.network_settings
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
    /// Consumes the builder and constructs a [`ListNetworkSettingsOutput`](crate::operation::list_network_settings::ListNetworkSettingsOutput).
    pub fn build(self) -> crate::operation::list_network_settings::ListNetworkSettingsOutput {
        crate::operation::list_network_settings::ListNetworkSettingsOutput {
            network_settings: self.network_settings,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
