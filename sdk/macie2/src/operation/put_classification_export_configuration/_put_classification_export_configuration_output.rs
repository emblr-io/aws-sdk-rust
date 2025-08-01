// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutClassificationExportConfigurationOutput {
    /// <p>The location where the data classification results are stored, and the encryption settings that are used when storing results in that location.</p>
    pub configuration: ::std::option::Option<crate::types::ClassificationExportConfiguration>,
    _request_id: Option<String>,
}
impl PutClassificationExportConfigurationOutput {
    /// <p>The location where the data classification results are stored, and the encryption settings that are used when storing results in that location.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::ClassificationExportConfiguration> {
        self.configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutClassificationExportConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutClassificationExportConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`PutClassificationExportConfigurationOutput`](crate::operation::put_classification_export_configuration::PutClassificationExportConfigurationOutput).
    pub fn builder() -> crate::operation::put_classification_export_configuration::builders::PutClassificationExportConfigurationOutputBuilder {
        crate::operation::put_classification_export_configuration::builders::PutClassificationExportConfigurationOutputBuilder::default()
    }
}

/// A builder for [`PutClassificationExportConfigurationOutput`](crate::operation::put_classification_export_configuration::PutClassificationExportConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutClassificationExportConfigurationOutputBuilder {
    pub(crate) configuration: ::std::option::Option<crate::types::ClassificationExportConfiguration>,
    _request_id: Option<String>,
}
impl PutClassificationExportConfigurationOutputBuilder {
    /// <p>The location where the data classification results are stored, and the encryption settings that are used when storing results in that location.</p>
    pub fn configuration(mut self, input: crate::types::ClassificationExportConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location where the data classification results are stored, and the encryption settings that are used when storing results in that location.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::ClassificationExportConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>The location where the data classification results are stored, and the encryption settings that are used when storing results in that location.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::ClassificationExportConfiguration> {
        &self.configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutClassificationExportConfigurationOutput`](crate::operation::put_classification_export_configuration::PutClassificationExportConfigurationOutput).
    pub fn build(self) -> crate::operation::put_classification_export_configuration::PutClassificationExportConfigurationOutput {
        crate::operation::put_classification_export_configuration::PutClassificationExportConfigurationOutput {
            configuration: self.configuration,
            _request_id: self._request_id,
        }
    }
}
