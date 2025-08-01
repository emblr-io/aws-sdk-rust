// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterContainerImageInput {
    /// <p>The name of the container service for which to register a container image.</p>
    pub service_name: ::std::option::Option<::std::string::String>,
    /// <p>The label for the container image when it's registered to the container service.</p>
    /// <p>Use a descriptive label that you can use to track the different versions of your registered container images.</p>
    /// <p>Use the <code>GetContainerImages</code> action to return the container images registered to a Lightsail container service. The label is the <code><imagelabel></imagelabel></code> portion of the following image name example:</p>
    /// <ul>
    /// <li>
    /// <p><code>:container-service-1.<imagelabel>
    /// .1
    /// </imagelabel></code></p></li>
    /// </ul>
    /// <p>If the name of your container service is <code>mycontainerservice</code>, and the label that you specify is <code>mystaticwebsite</code>, then the name of the registered container image will be <code>:mycontainerservice.mystaticwebsite.1</code>.</p>
    /// <p>The number at the end of these image name examples represents the version of the registered container image. If you push and register another container image to the same Lightsail container service, with the same label, then the version number for the new registered container image will be <code>2</code>. If you push and register another container image, the version number will be <code>3</code>, and so on.</p>
    pub label: ::std::option::Option<::std::string::String>,
    /// <p>The digest of the container image to be registered.</p>
    pub digest: ::std::option::Option<::std::string::String>,
}
impl RegisterContainerImageInput {
    /// <p>The name of the container service for which to register a container image.</p>
    pub fn service_name(&self) -> ::std::option::Option<&str> {
        self.service_name.as_deref()
    }
    /// <p>The label for the container image when it's registered to the container service.</p>
    /// <p>Use a descriptive label that you can use to track the different versions of your registered container images.</p>
    /// <p>Use the <code>GetContainerImages</code> action to return the container images registered to a Lightsail container service. The label is the <code><imagelabel></imagelabel></code> portion of the following image name example:</p>
    /// <ul>
    /// <li>
    /// <p><code>:container-service-1.<imagelabel>
    /// .1
    /// </imagelabel></code></p></li>
    /// </ul>
    /// <p>If the name of your container service is <code>mycontainerservice</code>, and the label that you specify is <code>mystaticwebsite</code>, then the name of the registered container image will be <code>:mycontainerservice.mystaticwebsite.1</code>.</p>
    /// <p>The number at the end of these image name examples represents the version of the registered container image. If you push and register another container image to the same Lightsail container service, with the same label, then the version number for the new registered container image will be <code>2</code>. If you push and register another container image, the version number will be <code>3</code>, and so on.</p>
    pub fn label(&self) -> ::std::option::Option<&str> {
        self.label.as_deref()
    }
    /// <p>The digest of the container image to be registered.</p>
    pub fn digest(&self) -> ::std::option::Option<&str> {
        self.digest.as_deref()
    }
}
impl RegisterContainerImageInput {
    /// Creates a new builder-style object to manufacture [`RegisterContainerImageInput`](crate::operation::register_container_image::RegisterContainerImageInput).
    pub fn builder() -> crate::operation::register_container_image::builders::RegisterContainerImageInputBuilder {
        crate::operation::register_container_image::builders::RegisterContainerImageInputBuilder::default()
    }
}

/// A builder for [`RegisterContainerImageInput`](crate::operation::register_container_image::RegisterContainerImageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterContainerImageInputBuilder {
    pub(crate) service_name: ::std::option::Option<::std::string::String>,
    pub(crate) label: ::std::option::Option<::std::string::String>,
    pub(crate) digest: ::std::option::Option<::std::string::String>,
}
impl RegisterContainerImageInputBuilder {
    /// <p>The name of the container service for which to register a container image.</p>
    /// This field is required.
    pub fn service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container service for which to register a container image.</p>
    pub fn set_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_name = input;
        self
    }
    /// <p>The name of the container service for which to register a container image.</p>
    pub fn get_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_name
    }
    /// <p>The label for the container image when it's registered to the container service.</p>
    /// <p>Use a descriptive label that you can use to track the different versions of your registered container images.</p>
    /// <p>Use the <code>GetContainerImages</code> action to return the container images registered to a Lightsail container service. The label is the <code><imagelabel></imagelabel></code> portion of the following image name example:</p>
    /// <ul>
    /// <li>
    /// <p><code>:container-service-1.<imagelabel>
    /// .1
    /// </imagelabel></code></p></li>
    /// </ul>
    /// <p>If the name of your container service is <code>mycontainerservice</code>, and the label that you specify is <code>mystaticwebsite</code>, then the name of the registered container image will be <code>:mycontainerservice.mystaticwebsite.1</code>.</p>
    /// <p>The number at the end of these image name examples represents the version of the registered container image. If you push and register another container image to the same Lightsail container service, with the same label, then the version number for the new registered container image will be <code>2</code>. If you push and register another container image, the version number will be <code>3</code>, and so on.</p>
    /// This field is required.
    pub fn label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The label for the container image when it's registered to the container service.</p>
    /// <p>Use a descriptive label that you can use to track the different versions of your registered container images.</p>
    /// <p>Use the <code>GetContainerImages</code> action to return the container images registered to a Lightsail container service. The label is the <code><imagelabel></imagelabel></code> portion of the following image name example:</p>
    /// <ul>
    /// <li>
    /// <p><code>:container-service-1.<imagelabel>
    /// .1
    /// </imagelabel></code></p></li>
    /// </ul>
    /// <p>If the name of your container service is <code>mycontainerservice</code>, and the label that you specify is <code>mystaticwebsite</code>, then the name of the registered container image will be <code>:mycontainerservice.mystaticwebsite.1</code>.</p>
    /// <p>The number at the end of these image name examples represents the version of the registered container image. If you push and register another container image to the same Lightsail container service, with the same label, then the version number for the new registered container image will be <code>2</code>. If you push and register another container image, the version number will be <code>3</code>, and so on.</p>
    pub fn set_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.label = input;
        self
    }
    /// <p>The label for the container image when it's registered to the container service.</p>
    /// <p>Use a descriptive label that you can use to track the different versions of your registered container images.</p>
    /// <p>Use the <code>GetContainerImages</code> action to return the container images registered to a Lightsail container service. The label is the <code><imagelabel></imagelabel></code> portion of the following image name example:</p>
    /// <ul>
    /// <li>
    /// <p><code>:container-service-1.<imagelabel>
    /// .1
    /// </imagelabel></code></p></li>
    /// </ul>
    /// <p>If the name of your container service is <code>mycontainerservice</code>, and the label that you specify is <code>mystaticwebsite</code>, then the name of the registered container image will be <code>:mycontainerservice.mystaticwebsite.1</code>.</p>
    /// <p>The number at the end of these image name examples represents the version of the registered container image. If you push and register another container image to the same Lightsail container service, with the same label, then the version number for the new registered container image will be <code>2</code>. If you push and register another container image, the version number will be <code>3</code>, and so on.</p>
    pub fn get_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.label
    }
    /// <p>The digest of the container image to be registered.</p>
    /// This field is required.
    pub fn digest(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.digest = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The digest of the container image to be registered.</p>
    pub fn set_digest(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.digest = input;
        self
    }
    /// <p>The digest of the container image to be registered.</p>
    pub fn get_digest(&self) -> &::std::option::Option<::std::string::String> {
        &self.digest
    }
    /// Consumes the builder and constructs a [`RegisterContainerImageInput`](crate::operation::register_container_image::RegisterContainerImageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::register_container_image::RegisterContainerImageInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::register_container_image::RegisterContainerImageInput {
            service_name: self.service_name,
            label: self.label,
            digest: self.digest,
        })
    }
}
