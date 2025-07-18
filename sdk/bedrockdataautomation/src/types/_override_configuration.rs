// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Override configuration
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OverrideConfiguration {
    /// Override Configuration of Document
    pub document: ::std::option::Option<crate::types::DocumentOverrideConfiguration>,
    /// Override Configuration of Image
    pub image: ::std::option::Option<crate::types::ImageOverrideConfiguration>,
    /// Override Configuration of Video
    pub video: ::std::option::Option<crate::types::VideoOverrideConfiguration>,
    /// Override Configuration of Audio
    pub audio: ::std::option::Option<crate::types::AudioOverrideConfiguration>,
    /// Configuration for routing file type to desired modality
    pub modality_routing: ::std::option::Option<crate::types::ModalityRoutingConfiguration>,
}
impl OverrideConfiguration {
    /// Override Configuration of Document
    pub fn document(&self) -> ::std::option::Option<&crate::types::DocumentOverrideConfiguration> {
        self.document.as_ref()
    }
    /// Override Configuration of Image
    pub fn image(&self) -> ::std::option::Option<&crate::types::ImageOverrideConfiguration> {
        self.image.as_ref()
    }
    /// Override Configuration of Video
    pub fn video(&self) -> ::std::option::Option<&crate::types::VideoOverrideConfiguration> {
        self.video.as_ref()
    }
    /// Override Configuration of Audio
    pub fn audio(&self) -> ::std::option::Option<&crate::types::AudioOverrideConfiguration> {
        self.audio.as_ref()
    }
    /// Configuration for routing file type to desired modality
    pub fn modality_routing(&self) -> ::std::option::Option<&crate::types::ModalityRoutingConfiguration> {
        self.modality_routing.as_ref()
    }
}
impl OverrideConfiguration {
    /// Creates a new builder-style object to manufacture [`OverrideConfiguration`](crate::types::OverrideConfiguration).
    pub fn builder() -> crate::types::builders::OverrideConfigurationBuilder {
        crate::types::builders::OverrideConfigurationBuilder::default()
    }
}

/// A builder for [`OverrideConfiguration`](crate::types::OverrideConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OverrideConfigurationBuilder {
    pub(crate) document: ::std::option::Option<crate::types::DocumentOverrideConfiguration>,
    pub(crate) image: ::std::option::Option<crate::types::ImageOverrideConfiguration>,
    pub(crate) video: ::std::option::Option<crate::types::VideoOverrideConfiguration>,
    pub(crate) audio: ::std::option::Option<crate::types::AudioOverrideConfiguration>,
    pub(crate) modality_routing: ::std::option::Option<crate::types::ModalityRoutingConfiguration>,
}
impl OverrideConfigurationBuilder {
    /// Override Configuration of Document
    pub fn document(mut self, input: crate::types::DocumentOverrideConfiguration) -> Self {
        self.document = ::std::option::Option::Some(input);
        self
    }
    /// Override Configuration of Document
    pub fn set_document(mut self, input: ::std::option::Option<crate::types::DocumentOverrideConfiguration>) -> Self {
        self.document = input;
        self
    }
    /// Override Configuration of Document
    pub fn get_document(&self) -> &::std::option::Option<crate::types::DocumentOverrideConfiguration> {
        &self.document
    }
    /// Override Configuration of Image
    pub fn image(mut self, input: crate::types::ImageOverrideConfiguration) -> Self {
        self.image = ::std::option::Option::Some(input);
        self
    }
    /// Override Configuration of Image
    pub fn set_image(mut self, input: ::std::option::Option<crate::types::ImageOverrideConfiguration>) -> Self {
        self.image = input;
        self
    }
    /// Override Configuration of Image
    pub fn get_image(&self) -> &::std::option::Option<crate::types::ImageOverrideConfiguration> {
        &self.image
    }
    /// Override Configuration of Video
    pub fn video(mut self, input: crate::types::VideoOverrideConfiguration) -> Self {
        self.video = ::std::option::Option::Some(input);
        self
    }
    /// Override Configuration of Video
    pub fn set_video(mut self, input: ::std::option::Option<crate::types::VideoOverrideConfiguration>) -> Self {
        self.video = input;
        self
    }
    /// Override Configuration of Video
    pub fn get_video(&self) -> &::std::option::Option<crate::types::VideoOverrideConfiguration> {
        &self.video
    }
    /// Override Configuration of Audio
    pub fn audio(mut self, input: crate::types::AudioOverrideConfiguration) -> Self {
        self.audio = ::std::option::Option::Some(input);
        self
    }
    /// Override Configuration of Audio
    pub fn set_audio(mut self, input: ::std::option::Option<crate::types::AudioOverrideConfiguration>) -> Self {
        self.audio = input;
        self
    }
    /// Override Configuration of Audio
    pub fn get_audio(&self) -> &::std::option::Option<crate::types::AudioOverrideConfiguration> {
        &self.audio
    }
    /// Configuration for routing file type to desired modality
    pub fn modality_routing(mut self, input: crate::types::ModalityRoutingConfiguration) -> Self {
        self.modality_routing = ::std::option::Option::Some(input);
        self
    }
    /// Configuration for routing file type to desired modality
    pub fn set_modality_routing(mut self, input: ::std::option::Option<crate::types::ModalityRoutingConfiguration>) -> Self {
        self.modality_routing = input;
        self
    }
    /// Configuration for routing file type to desired modality
    pub fn get_modality_routing(&self) -> &::std::option::Option<crate::types::ModalityRoutingConfiguration> {
        &self.modality_routing
    }
    /// Consumes the builder and constructs a [`OverrideConfiguration`](crate::types::OverrideConfiguration).
    pub fn build(self) -> crate::types::OverrideConfiguration {
        crate::types::OverrideConfiguration {
            document: self.document,
            image: self.image,
            video: self.video,
            audio: self.audio,
            modality_routing: self.modality_routing,
        }
    }
}
