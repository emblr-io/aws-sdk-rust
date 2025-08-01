// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutImageScanningConfigurationInput {
    /// <p>The Amazon Web Services account ID associated with the registry that contains the repository in which to update the image scanning configuration setting. If you do not specify a registry, the default registry is assumed.</p>
    pub registry_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the repository in which to update the image scanning configuration setting.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The image scanning configuration for the repository. This setting determines whether images are scanned for known vulnerabilities after being pushed to the repository.</p>
    pub image_scanning_configuration: ::std::option::Option<crate::types::ImageScanningConfiguration>,
}
impl PutImageScanningConfigurationInput {
    /// <p>The Amazon Web Services account ID associated with the registry that contains the repository in which to update the image scanning configuration setting. If you do not specify a registry, the default registry is assumed.</p>
    pub fn registry_id(&self) -> ::std::option::Option<&str> {
        self.registry_id.as_deref()
    }
    /// <p>The name of the repository in which to update the image scanning configuration setting.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The image scanning configuration for the repository. This setting determines whether images are scanned for known vulnerabilities after being pushed to the repository.</p>
    pub fn image_scanning_configuration(&self) -> ::std::option::Option<&crate::types::ImageScanningConfiguration> {
        self.image_scanning_configuration.as_ref()
    }
}
impl PutImageScanningConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutImageScanningConfigurationInput`](crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationInput).
    pub fn builder() -> crate::operation::put_image_scanning_configuration::builders::PutImageScanningConfigurationInputBuilder {
        crate::operation::put_image_scanning_configuration::builders::PutImageScanningConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutImageScanningConfigurationInput`](crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutImageScanningConfigurationInputBuilder {
    pub(crate) registry_id: ::std::option::Option<::std::string::String>,
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) image_scanning_configuration: ::std::option::Option<crate::types::ImageScanningConfiguration>,
}
impl PutImageScanningConfigurationInputBuilder {
    /// <p>The Amazon Web Services account ID associated with the registry that contains the repository in which to update the image scanning configuration setting. If you do not specify a registry, the default registry is assumed.</p>
    pub fn registry_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registry_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID associated with the registry that contains the repository in which to update the image scanning configuration setting. If you do not specify a registry, the default registry is assumed.</p>
    pub fn set_registry_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registry_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID associated with the registry that contains the repository in which to update the image scanning configuration setting. If you do not specify a registry, the default registry is assumed.</p>
    pub fn get_registry_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.registry_id
    }
    /// <p>The name of the repository in which to update the image scanning configuration setting.</p>
    /// This field is required.
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository in which to update the image scanning configuration setting.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the repository in which to update the image scanning configuration setting.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>The image scanning configuration for the repository. This setting determines whether images are scanned for known vulnerabilities after being pushed to the repository.</p>
    /// This field is required.
    pub fn image_scanning_configuration(mut self, input: crate::types::ImageScanningConfiguration) -> Self {
        self.image_scanning_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image scanning configuration for the repository. This setting determines whether images are scanned for known vulnerabilities after being pushed to the repository.</p>
    pub fn set_image_scanning_configuration(mut self, input: ::std::option::Option<crate::types::ImageScanningConfiguration>) -> Self {
        self.image_scanning_configuration = input;
        self
    }
    /// <p>The image scanning configuration for the repository. This setting determines whether images are scanned for known vulnerabilities after being pushed to the repository.</p>
    pub fn get_image_scanning_configuration(&self) -> &::std::option::Option<crate::types::ImageScanningConfiguration> {
        &self.image_scanning_configuration
    }
    /// Consumes the builder and constructs a [`PutImageScanningConfigurationInput`](crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_image_scanning_configuration::PutImageScanningConfigurationInput {
            registry_id: self.registry_id,
            repository_name: self.repository_name,
            image_scanning_configuration: self.image_scanning_configuration,
        })
    }
}
