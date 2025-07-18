// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The specifications for a worker type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkerTypeSpecification {
    /// <p>The image configuration for a worker type.</p>
    pub image_configuration: ::std::option::Option<crate::types::ImageConfiguration>,
}
impl WorkerTypeSpecification {
    /// <p>The image configuration for a worker type.</p>
    pub fn image_configuration(&self) -> ::std::option::Option<&crate::types::ImageConfiguration> {
        self.image_configuration.as_ref()
    }
}
impl WorkerTypeSpecification {
    /// Creates a new builder-style object to manufacture [`WorkerTypeSpecification`](crate::types::WorkerTypeSpecification).
    pub fn builder() -> crate::types::builders::WorkerTypeSpecificationBuilder {
        crate::types::builders::WorkerTypeSpecificationBuilder::default()
    }
}

/// A builder for [`WorkerTypeSpecification`](crate::types::WorkerTypeSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkerTypeSpecificationBuilder {
    pub(crate) image_configuration: ::std::option::Option<crate::types::ImageConfiguration>,
}
impl WorkerTypeSpecificationBuilder {
    /// <p>The image configuration for a worker type.</p>
    pub fn image_configuration(mut self, input: crate::types::ImageConfiguration) -> Self {
        self.image_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image configuration for a worker type.</p>
    pub fn set_image_configuration(mut self, input: ::std::option::Option<crate::types::ImageConfiguration>) -> Self {
        self.image_configuration = input;
        self
    }
    /// <p>The image configuration for a worker type.</p>
    pub fn get_image_configuration(&self) -> &::std::option::Option<crate::types::ImageConfiguration> {
        &self.image_configuration
    }
    /// Consumes the builder and constructs a [`WorkerTypeSpecification`](crate::types::WorkerTypeSpecification).
    pub fn build(self) -> crate::types::WorkerTypeSpecification {
        crate::types::WorkerTypeSpecification {
            image_configuration: self.image_configuration,
        }
    }
}
