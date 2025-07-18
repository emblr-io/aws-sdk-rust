// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The static file.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StaticFile {
    /// <p>The image static file.</p>
    pub image_static_file: ::std::option::Option<crate::types::ImageStaticFile>,
    /// <p>The spacial static file.</p>
    pub spatial_static_file: ::std::option::Option<crate::types::SpatialStaticFile>,
}
impl StaticFile {
    /// <p>The image static file.</p>
    pub fn image_static_file(&self) -> ::std::option::Option<&crate::types::ImageStaticFile> {
        self.image_static_file.as_ref()
    }
    /// <p>The spacial static file.</p>
    pub fn spatial_static_file(&self) -> ::std::option::Option<&crate::types::SpatialStaticFile> {
        self.spatial_static_file.as_ref()
    }
}
impl StaticFile {
    /// Creates a new builder-style object to manufacture [`StaticFile`](crate::types::StaticFile).
    pub fn builder() -> crate::types::builders::StaticFileBuilder {
        crate::types::builders::StaticFileBuilder::default()
    }
}

/// A builder for [`StaticFile`](crate::types::StaticFile).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StaticFileBuilder {
    pub(crate) image_static_file: ::std::option::Option<crate::types::ImageStaticFile>,
    pub(crate) spatial_static_file: ::std::option::Option<crate::types::SpatialStaticFile>,
}
impl StaticFileBuilder {
    /// <p>The image static file.</p>
    pub fn image_static_file(mut self, input: crate::types::ImageStaticFile) -> Self {
        self.image_static_file = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image static file.</p>
    pub fn set_image_static_file(mut self, input: ::std::option::Option<crate::types::ImageStaticFile>) -> Self {
        self.image_static_file = input;
        self
    }
    /// <p>The image static file.</p>
    pub fn get_image_static_file(&self) -> &::std::option::Option<crate::types::ImageStaticFile> {
        &self.image_static_file
    }
    /// <p>The spacial static file.</p>
    pub fn spatial_static_file(mut self, input: crate::types::SpatialStaticFile) -> Self {
        self.spatial_static_file = ::std::option::Option::Some(input);
        self
    }
    /// <p>The spacial static file.</p>
    pub fn set_spatial_static_file(mut self, input: ::std::option::Option<crate::types::SpatialStaticFile>) -> Self {
        self.spatial_static_file = input;
        self
    }
    /// <p>The spacial static file.</p>
    pub fn get_spatial_static_file(&self) -> &::std::option::Option<crate::types::SpatialStaticFile> {
        &self.spatial_static_file
    }
    /// Consumes the builder and constructs a [`StaticFile`](crate::types::StaticFile).
    pub fn build(self) -> crate::types::StaticFile {
        crate::types::StaticFile {
            image_static_file: self.image_static_file,
            spatial_static_file: self.spatial_static_file,
        }
    }
}
