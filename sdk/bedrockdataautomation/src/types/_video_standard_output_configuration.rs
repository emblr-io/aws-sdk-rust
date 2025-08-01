// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Standard Output Configuration of Video
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VideoStandardOutputConfiguration {
    /// Standard Extraction Configuration of Video
    pub extraction: ::std::option::Option<crate::types::VideoStandardExtraction>,
    /// Standard Generative Field Configuration of Video
    pub generative_field: ::std::option::Option<crate::types::VideoStandardGenerativeField>,
}
impl VideoStandardOutputConfiguration {
    /// Standard Extraction Configuration of Video
    pub fn extraction(&self) -> ::std::option::Option<&crate::types::VideoStandardExtraction> {
        self.extraction.as_ref()
    }
    /// Standard Generative Field Configuration of Video
    pub fn generative_field(&self) -> ::std::option::Option<&crate::types::VideoStandardGenerativeField> {
        self.generative_field.as_ref()
    }
}
impl VideoStandardOutputConfiguration {
    /// Creates a new builder-style object to manufacture [`VideoStandardOutputConfiguration`](crate::types::VideoStandardOutputConfiguration).
    pub fn builder() -> crate::types::builders::VideoStandardOutputConfigurationBuilder {
        crate::types::builders::VideoStandardOutputConfigurationBuilder::default()
    }
}

/// A builder for [`VideoStandardOutputConfiguration`](crate::types::VideoStandardOutputConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VideoStandardOutputConfigurationBuilder {
    pub(crate) extraction: ::std::option::Option<crate::types::VideoStandardExtraction>,
    pub(crate) generative_field: ::std::option::Option<crate::types::VideoStandardGenerativeField>,
}
impl VideoStandardOutputConfigurationBuilder {
    /// Standard Extraction Configuration of Video
    pub fn extraction(mut self, input: crate::types::VideoStandardExtraction) -> Self {
        self.extraction = ::std::option::Option::Some(input);
        self
    }
    /// Standard Extraction Configuration of Video
    pub fn set_extraction(mut self, input: ::std::option::Option<crate::types::VideoStandardExtraction>) -> Self {
        self.extraction = input;
        self
    }
    /// Standard Extraction Configuration of Video
    pub fn get_extraction(&self) -> &::std::option::Option<crate::types::VideoStandardExtraction> {
        &self.extraction
    }
    /// Standard Generative Field Configuration of Video
    pub fn generative_field(mut self, input: crate::types::VideoStandardGenerativeField) -> Self {
        self.generative_field = ::std::option::Option::Some(input);
        self
    }
    /// Standard Generative Field Configuration of Video
    pub fn set_generative_field(mut self, input: ::std::option::Option<crate::types::VideoStandardGenerativeField>) -> Self {
        self.generative_field = input;
        self
    }
    /// Standard Generative Field Configuration of Video
    pub fn get_generative_field(&self) -> &::std::option::Option<crate::types::VideoStandardGenerativeField> {
        &self.generative_field
    }
    /// Consumes the builder and constructs a [`VideoStandardOutputConfiguration`](crate::types::VideoStandardOutputConfiguration).
    pub fn build(self) -> crate::types::VideoStandardOutputConfiguration {
        crate::types::VideoStandardOutputConfiguration {
            extraction: self.extraction,
            generative_field: self.generative_field,
        }
    }
}
