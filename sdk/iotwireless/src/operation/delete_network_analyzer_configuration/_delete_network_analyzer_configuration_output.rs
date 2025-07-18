// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteNetworkAnalyzerConfigurationOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteNetworkAnalyzerConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteNetworkAnalyzerConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DeleteNetworkAnalyzerConfigurationOutput`](crate::operation::delete_network_analyzer_configuration::DeleteNetworkAnalyzerConfigurationOutput).
    pub fn builder() -> crate::operation::delete_network_analyzer_configuration::builders::DeleteNetworkAnalyzerConfigurationOutputBuilder {
        crate::operation::delete_network_analyzer_configuration::builders::DeleteNetworkAnalyzerConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DeleteNetworkAnalyzerConfigurationOutput`](crate::operation::delete_network_analyzer_configuration::DeleteNetworkAnalyzerConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteNetworkAnalyzerConfigurationOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteNetworkAnalyzerConfigurationOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteNetworkAnalyzerConfigurationOutput`](crate::operation::delete_network_analyzer_configuration::DeleteNetworkAnalyzerConfigurationOutput).
    pub fn build(self) -> crate::operation::delete_network_analyzer_configuration::DeleteNetworkAnalyzerConfigurationOutput {
        crate::operation::delete_network_analyzer_configuration::DeleteNetworkAnalyzerConfigurationOutput {
            _request_id: self._request_id,
        }
    }
}
