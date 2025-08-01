// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutRetentionConfigurationOutput {
    /// <p>Returns a retention configuration object.</p>
    pub retention_configuration: ::std::option::Option<crate::types::RetentionConfiguration>,
    _request_id: Option<String>,
}
impl PutRetentionConfigurationOutput {
    /// <p>Returns a retention configuration object.</p>
    pub fn retention_configuration(&self) -> ::std::option::Option<&crate::types::RetentionConfiguration> {
        self.retention_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutRetentionConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutRetentionConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`PutRetentionConfigurationOutput`](crate::operation::put_retention_configuration::PutRetentionConfigurationOutput).
    pub fn builder() -> crate::operation::put_retention_configuration::builders::PutRetentionConfigurationOutputBuilder {
        crate::operation::put_retention_configuration::builders::PutRetentionConfigurationOutputBuilder::default()
    }
}

/// A builder for [`PutRetentionConfigurationOutput`](crate::operation::put_retention_configuration::PutRetentionConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutRetentionConfigurationOutputBuilder {
    pub(crate) retention_configuration: ::std::option::Option<crate::types::RetentionConfiguration>,
    _request_id: Option<String>,
}
impl PutRetentionConfigurationOutputBuilder {
    /// <p>Returns a retention configuration object.</p>
    pub fn retention_configuration(mut self, input: crate::types::RetentionConfiguration) -> Self {
        self.retention_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns a retention configuration object.</p>
    pub fn set_retention_configuration(mut self, input: ::std::option::Option<crate::types::RetentionConfiguration>) -> Self {
        self.retention_configuration = input;
        self
    }
    /// <p>Returns a retention configuration object.</p>
    pub fn get_retention_configuration(&self) -> &::std::option::Option<crate::types::RetentionConfiguration> {
        &self.retention_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutRetentionConfigurationOutput`](crate::operation::put_retention_configuration::PutRetentionConfigurationOutput).
    pub fn build(self) -> crate::operation::put_retention_configuration::PutRetentionConfigurationOutput {
        crate::operation::put_retention_configuration::PutRetentionConfigurationOutput {
            retention_configuration: self.retention_configuration,
            _request_id: self._request_id,
        }
    }
}
