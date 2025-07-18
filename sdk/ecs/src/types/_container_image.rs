// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details about the container image a service revision uses.</p>
/// <p>To ensure that all tasks in a service use the same container image, Amazon ECS resolves container image names and any image tags specified in the task definition to container image digests.</p>
/// <p>After the container image digest has been established, Amazon ECS uses the digest to start any other desired tasks, and for any future service and service revision updates. This leads to all tasks in a service always running identical container images, resulting in version consistency for your software. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-ecs.html#deployment-container-image-stability">Container image resolution</a> in the Amazon ECS Developer Guide.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContainerImage {
    /// <p>The name of the container.</p>
    pub container_name: ::std::option::Option<::std::string::String>,
    /// <p>The container image digest.</p>
    pub image_digest: ::std::option::Option<::std::string::String>,
    /// <p>The container image.</p>
    pub image: ::std::option::Option<::std::string::String>,
}
impl ContainerImage {
    /// <p>The name of the container.</p>
    pub fn container_name(&self) -> ::std::option::Option<&str> {
        self.container_name.as_deref()
    }
    /// <p>The container image digest.</p>
    pub fn image_digest(&self) -> ::std::option::Option<&str> {
        self.image_digest.as_deref()
    }
    /// <p>The container image.</p>
    pub fn image(&self) -> ::std::option::Option<&str> {
        self.image.as_deref()
    }
}
impl ContainerImage {
    /// Creates a new builder-style object to manufacture [`ContainerImage`](crate::types::ContainerImage).
    pub fn builder() -> crate::types::builders::ContainerImageBuilder {
        crate::types::builders::ContainerImageBuilder::default()
    }
}

/// A builder for [`ContainerImage`](crate::types::ContainerImage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContainerImageBuilder {
    pub(crate) container_name: ::std::option::Option<::std::string::String>,
    pub(crate) image_digest: ::std::option::Option<::std::string::String>,
    pub(crate) image: ::std::option::Option<::std::string::String>,
}
impl ContainerImageBuilder {
    /// <p>The name of the container.</p>
    pub fn container_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container.</p>
    pub fn set_container_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_name = input;
        self
    }
    /// <p>The name of the container.</p>
    pub fn get_container_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_name
    }
    /// <p>The container image digest.</p>
    pub fn image_digest(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_digest = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The container image digest.</p>
    pub fn set_image_digest(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_digest = input;
        self
    }
    /// <p>The container image digest.</p>
    pub fn get_image_digest(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_digest
    }
    /// <p>The container image.</p>
    pub fn image(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The container image.</p>
    pub fn set_image(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image = input;
        self
    }
    /// <p>The container image.</p>
    pub fn get_image(&self) -> &::std::option::Option<::std::string::String> {
        &self.image
    }
    /// Consumes the builder and constructs a [`ContainerImage`](crate::types::ContainerImage).
    pub fn build(self) -> crate::types::ContainerImage {
        crate::types::ContainerImage {
            container_name: self.container_name,
            image_digest: self.image_digest,
            image: self.image,
        }
    }
}
