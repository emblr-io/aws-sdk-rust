// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An empty element returned on a successful request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateConfigurationSetTrackingOptionsOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for CreateConfigurationSetTrackingOptionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateConfigurationSetTrackingOptionsOutput {
    /// Creates a new builder-style object to manufacture [`CreateConfigurationSetTrackingOptionsOutput`](crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsOutput).
    pub fn builder() -> crate::operation::create_configuration_set_tracking_options::builders::CreateConfigurationSetTrackingOptionsOutputBuilder {
        crate::operation::create_configuration_set_tracking_options::builders::CreateConfigurationSetTrackingOptionsOutputBuilder::default()
    }
}

/// A builder for [`CreateConfigurationSetTrackingOptionsOutput`](crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateConfigurationSetTrackingOptionsOutputBuilder {
    _request_id: Option<String>,
}
impl CreateConfigurationSetTrackingOptionsOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateConfigurationSetTrackingOptionsOutput`](crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsOutput).
    pub fn build(self) -> crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsOutput {
        crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsOutput {
            _request_id: self._request_id,
        }
    }
}
