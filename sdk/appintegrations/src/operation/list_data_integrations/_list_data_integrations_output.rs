// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDataIntegrationsOutput {
    /// <p>The DataIntegrations associated with this account.</p>
    pub data_integrations: ::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationSummary>>,
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDataIntegrationsOutput {
    /// <p>The DataIntegrations associated with this account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_integrations.is_none()`.
    pub fn data_integrations(&self) -> &[crate::types::DataIntegrationSummary] {
        self.data_integrations.as_deref().unwrap_or_default()
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDataIntegrationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDataIntegrationsOutput {
    /// Creates a new builder-style object to manufacture [`ListDataIntegrationsOutput`](crate::operation::list_data_integrations::ListDataIntegrationsOutput).
    pub fn builder() -> crate::operation::list_data_integrations::builders::ListDataIntegrationsOutputBuilder {
        crate::operation::list_data_integrations::builders::ListDataIntegrationsOutputBuilder::default()
    }
}

/// A builder for [`ListDataIntegrationsOutput`](crate::operation::list_data_integrations::ListDataIntegrationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDataIntegrationsOutputBuilder {
    pub(crate) data_integrations: ::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDataIntegrationsOutputBuilder {
    /// Appends an item to `data_integrations`.
    ///
    /// To override the contents of this collection use [`set_data_integrations`](Self::set_data_integrations).
    ///
    /// <p>The DataIntegrations associated with this account.</p>
    pub fn data_integrations(mut self, input: crate::types::DataIntegrationSummary) -> Self {
        let mut v = self.data_integrations.unwrap_or_default();
        v.push(input);
        self.data_integrations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The DataIntegrations associated with this account.</p>
    pub fn set_data_integrations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationSummary>>) -> Self {
        self.data_integrations = input;
        self
    }
    /// <p>The DataIntegrations associated with this account.</p>
    pub fn get_data_integrations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationSummary>> {
        &self.data_integrations
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
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
    /// Consumes the builder and constructs a [`ListDataIntegrationsOutput`](crate::operation::list_data_integrations::ListDataIntegrationsOutput).
    pub fn build(self) -> crate::operation::list_data_integrations::ListDataIntegrationsOutput {
        crate::operation::list_data_integrations::ListDataIntegrationsOutput {
            data_integrations: self.data_integrations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
