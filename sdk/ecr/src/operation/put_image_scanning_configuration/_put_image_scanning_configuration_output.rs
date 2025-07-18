// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutImageScanningConfigurationOutput {
    /// <p>The registry ID associated with the request.</p>
    pub registry_id: ::std::option::Option<::std::string::String>,
    /// <p>The repository name associated with the request.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The image scanning configuration setting for the repository.</p>
    pub image_scanning_configuration: ::std::option::Option<crate::types::ImageScanningConfiguration>,
    _request_id: Option<String>,
}
impl PutImageScanningConfigurationOutput {
    /// <p>The registry ID associated with the request.</p>
    pub fn registry_id(&self) -> ::std::option::Option<&str> {
        self.registry_id.as_deref()
    }
    /// <p>The repository name associated with the request.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The image scanning configuration setting for the repository.</p>
    pub fn image_scanning_configuration(&self) -> ::std::option::Option<&crate::types::ImageScanningConfiguration> {
        self.image_scanning_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutImageScanningConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutImageScanningConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`PutImageScanningConfigurationOutput`](crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationOutput).
    pub fn builder() -> crate::operation::put_image_scanning_configuration::builders::PutImageScanningConfigurationOutputBuilder {
        crate::operation::put_image_scanning_configuration::builders::PutImageScanningConfigurationOutputBuilder::default()
    }
}

/// A builder for [`PutImageScanningConfigurationOutput`](crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutImageScanningConfigurationOutputBuilder {
    pub(crate) registry_id: ::std::option::Option<::std::string::String>,
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) image_scanning_configuration: ::std::option::Option<crate::types::ImageScanningConfiguration>,
    _request_id: Option<String>,
}
impl PutImageScanningConfigurationOutputBuilder {
    /// <p>The registry ID associated with the request.</p>
    pub fn registry_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registry_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The registry ID associated with the request.</p>
    pub fn set_registry_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registry_id = input;
        self
    }
    /// <p>The registry ID associated with the request.</p>
    pub fn get_registry_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.registry_id
    }
    /// <p>The repository name associated with the request.</p>
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The repository name associated with the request.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The repository name associated with the request.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>The image scanning configuration setting for the repository.</p>
    pub fn image_scanning_configuration(mut self, input: crate::types::ImageScanningConfiguration) -> Self {
        self.image_scanning_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image scanning configuration setting for the repository.</p>
    pub fn set_image_scanning_configuration(mut self, input: ::std::option::Option<crate::types::ImageScanningConfiguration>) -> Self {
        self.image_scanning_configuration = input;
        self
    }
    /// <p>The image scanning configuration setting for the repository.</p>
    pub fn get_image_scanning_configuration(&self) -> &::std::option::Option<crate::types::ImageScanningConfiguration> {
        &self.image_scanning_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutImageScanningConfigurationOutput`](crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationOutput).
    pub fn build(self) -> crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationOutput {
        crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationOutput {
            registry_id: self.registry_id,
            repository_name: self.repository_name,
            image_scanning_configuration: self.image_scanning_configuration,
            _request_id: self._request_id,
        }
    }
}
