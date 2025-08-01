// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An HTTP 200 response if the request succeeds, or an error message if the request fails.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutConfigurationSetArchivingOptionsOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PutConfigurationSetArchivingOptionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutConfigurationSetArchivingOptionsOutput {
    /// Creates a new builder-style object to manufacture [`PutConfigurationSetArchivingOptionsOutput`](crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsOutput).
    pub fn builder() -> crate::operation::put_configuration_set_archiving_options::builders::PutConfigurationSetArchivingOptionsOutputBuilder {
        crate::operation::put_configuration_set_archiving_options::builders::PutConfigurationSetArchivingOptionsOutputBuilder::default()
    }
}

/// A builder for [`PutConfigurationSetArchivingOptionsOutput`](crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutConfigurationSetArchivingOptionsOutputBuilder {
    _request_id: Option<String>,
}
impl PutConfigurationSetArchivingOptionsOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutConfigurationSetArchivingOptionsOutput`](crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsOutput).
    pub fn build(self) -> crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsOutput {
        crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsOutput {
            _request_id: self._request_id,
        }
    }
}
