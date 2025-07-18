// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Configuration for routing file type to desired modality
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModalityRoutingConfiguration {
    /// Desired Modality types
    pub jpeg: ::std::option::Option<crate::types::DesiredModality>,
    /// Desired Modality types
    pub png: ::std::option::Option<crate::types::DesiredModality>,
    /// Desired Modality types
    pub mp4: ::std::option::Option<crate::types::DesiredModality>,
    /// Desired Modality types
    pub mov: ::std::option::Option<crate::types::DesiredModality>,
}
impl ModalityRoutingConfiguration {
    /// Desired Modality types
    pub fn jpeg(&self) -> ::std::option::Option<&crate::types::DesiredModality> {
        self.jpeg.as_ref()
    }
    /// Desired Modality types
    pub fn png(&self) -> ::std::option::Option<&crate::types::DesiredModality> {
        self.png.as_ref()
    }
    /// Desired Modality types
    pub fn mp4(&self) -> ::std::option::Option<&crate::types::DesiredModality> {
        self.mp4.as_ref()
    }
    /// Desired Modality types
    pub fn mov(&self) -> ::std::option::Option<&crate::types::DesiredModality> {
        self.mov.as_ref()
    }
}
impl ModalityRoutingConfiguration {
    /// Creates a new builder-style object to manufacture [`ModalityRoutingConfiguration`](crate::types::ModalityRoutingConfiguration).
    pub fn builder() -> crate::types::builders::ModalityRoutingConfigurationBuilder {
        crate::types::builders::ModalityRoutingConfigurationBuilder::default()
    }
}

/// A builder for [`ModalityRoutingConfiguration`](crate::types::ModalityRoutingConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModalityRoutingConfigurationBuilder {
    pub(crate) jpeg: ::std::option::Option<crate::types::DesiredModality>,
    pub(crate) png: ::std::option::Option<crate::types::DesiredModality>,
    pub(crate) mp4: ::std::option::Option<crate::types::DesiredModality>,
    pub(crate) mov: ::std::option::Option<crate::types::DesiredModality>,
}
impl ModalityRoutingConfigurationBuilder {
    /// Desired Modality types
    pub fn jpeg(mut self, input: crate::types::DesiredModality) -> Self {
        self.jpeg = ::std::option::Option::Some(input);
        self
    }
    /// Desired Modality types
    pub fn set_jpeg(mut self, input: ::std::option::Option<crate::types::DesiredModality>) -> Self {
        self.jpeg = input;
        self
    }
    /// Desired Modality types
    pub fn get_jpeg(&self) -> &::std::option::Option<crate::types::DesiredModality> {
        &self.jpeg
    }
    /// Desired Modality types
    pub fn png(mut self, input: crate::types::DesiredModality) -> Self {
        self.png = ::std::option::Option::Some(input);
        self
    }
    /// Desired Modality types
    pub fn set_png(mut self, input: ::std::option::Option<crate::types::DesiredModality>) -> Self {
        self.png = input;
        self
    }
    /// Desired Modality types
    pub fn get_png(&self) -> &::std::option::Option<crate::types::DesiredModality> {
        &self.png
    }
    /// Desired Modality types
    pub fn mp4(mut self, input: crate::types::DesiredModality) -> Self {
        self.mp4 = ::std::option::Option::Some(input);
        self
    }
    /// Desired Modality types
    pub fn set_mp4(mut self, input: ::std::option::Option<crate::types::DesiredModality>) -> Self {
        self.mp4 = input;
        self
    }
    /// Desired Modality types
    pub fn get_mp4(&self) -> &::std::option::Option<crate::types::DesiredModality> {
        &self.mp4
    }
    /// Desired Modality types
    pub fn mov(mut self, input: crate::types::DesiredModality) -> Self {
        self.mov = ::std::option::Option::Some(input);
        self
    }
    /// Desired Modality types
    pub fn set_mov(mut self, input: ::std::option::Option<crate::types::DesiredModality>) -> Self {
        self.mov = input;
        self
    }
    /// Desired Modality types
    pub fn get_mov(&self) -> &::std::option::Option<crate::types::DesiredModality> {
        &self.mov
    }
    /// Consumes the builder and constructs a [`ModalityRoutingConfiguration`](crate::types::ModalityRoutingConfiguration).
    pub fn build(self) -> crate::types::ModalityRoutingConfiguration {
        crate::types::ModalityRoutingConfiguration {
            jpeg: self.jpeg,
            png: self.png,
            mp4: self.mp4,
            mov: self.mov,
        }
    }
}
