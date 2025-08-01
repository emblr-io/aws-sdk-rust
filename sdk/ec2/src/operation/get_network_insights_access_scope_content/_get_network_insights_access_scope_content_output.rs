// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetNetworkInsightsAccessScopeContentOutput {
    /// <p>The Network Access Scope content.</p>
    pub network_insights_access_scope_content: ::std::option::Option<crate::types::NetworkInsightsAccessScopeContent>,
    _request_id: Option<String>,
}
impl GetNetworkInsightsAccessScopeContentOutput {
    /// <p>The Network Access Scope content.</p>
    pub fn network_insights_access_scope_content(&self) -> ::std::option::Option<&crate::types::NetworkInsightsAccessScopeContent> {
        self.network_insights_access_scope_content.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetNetworkInsightsAccessScopeContentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetNetworkInsightsAccessScopeContentOutput {
    /// Creates a new builder-style object to manufacture [`GetNetworkInsightsAccessScopeContentOutput`](crate::operation::get_network_insights_access_scope_content::GetNetworkInsightsAccessScopeContentOutput).
    pub fn builder() -> crate::operation::get_network_insights_access_scope_content::builders::GetNetworkInsightsAccessScopeContentOutputBuilder {
        crate::operation::get_network_insights_access_scope_content::builders::GetNetworkInsightsAccessScopeContentOutputBuilder::default()
    }
}

/// A builder for [`GetNetworkInsightsAccessScopeContentOutput`](crate::operation::get_network_insights_access_scope_content::GetNetworkInsightsAccessScopeContentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetNetworkInsightsAccessScopeContentOutputBuilder {
    pub(crate) network_insights_access_scope_content: ::std::option::Option<crate::types::NetworkInsightsAccessScopeContent>,
    _request_id: Option<String>,
}
impl GetNetworkInsightsAccessScopeContentOutputBuilder {
    /// <p>The Network Access Scope content.</p>
    pub fn network_insights_access_scope_content(mut self, input: crate::types::NetworkInsightsAccessScopeContent) -> Self {
        self.network_insights_access_scope_content = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Network Access Scope content.</p>
    pub fn set_network_insights_access_scope_content(
        mut self,
        input: ::std::option::Option<crate::types::NetworkInsightsAccessScopeContent>,
    ) -> Self {
        self.network_insights_access_scope_content = input;
        self
    }
    /// <p>The Network Access Scope content.</p>
    pub fn get_network_insights_access_scope_content(&self) -> &::std::option::Option<crate::types::NetworkInsightsAccessScopeContent> {
        &self.network_insights_access_scope_content
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetNetworkInsightsAccessScopeContentOutput`](crate::operation::get_network_insights_access_scope_content::GetNetworkInsightsAccessScopeContentOutput).
    pub fn build(self) -> crate::operation::get_network_insights_access_scope_content::GetNetworkInsightsAccessScopeContentOutput {
        crate::operation::get_network_insights_access_scope_content::GetNetworkInsightsAccessScopeContentOutput {
            network_insights_access_scope_content: self.network_insights_access_scope_content,
            _request_id: self._request_id,
        }
    }
}
