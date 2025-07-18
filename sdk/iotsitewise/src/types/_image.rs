// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains an image that is one of the following:</p>
/// <ul>
/// <li>
/// <p>An image file. Choose this option to upload a new image.</p></li>
/// <li>
/// <p>The ID of an existing image. Choose this option to keep an existing image.</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Image {
    /// <p>The ID of an existing image. Specify this parameter to keep an existing image.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>Contains an image file.</p>
    pub file: ::std::option::Option<crate::types::ImageFile>,
}
impl Image {
    /// <p>The ID of an existing image. Specify this parameter to keep an existing image.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>Contains an image file.</p>
    pub fn file(&self) -> ::std::option::Option<&crate::types::ImageFile> {
        self.file.as_ref()
    }
}
impl Image {
    /// Creates a new builder-style object to manufacture [`Image`](crate::types::Image).
    pub fn builder() -> crate::types::builders::ImageBuilder {
        crate::types::builders::ImageBuilder::default()
    }
}

/// A builder for [`Image`](crate::types::Image).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImageBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) file: ::std::option::Option<crate::types::ImageFile>,
}
impl ImageBuilder {
    /// <p>The ID of an existing image. Specify this parameter to keep an existing image.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of an existing image. Specify this parameter to keep an existing image.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of an existing image. Specify this parameter to keep an existing image.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Contains an image file.</p>
    pub fn file(mut self, input: crate::types::ImageFile) -> Self {
        self.file = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains an image file.</p>
    pub fn set_file(mut self, input: ::std::option::Option<crate::types::ImageFile>) -> Self {
        self.file = input;
        self
    }
    /// <p>Contains an image file.</p>
    pub fn get_file(&self) -> &::std::option::Option<crate::types::ImageFile> {
        &self.file
    }
    /// Consumes the builder and constructs a [`Image`](crate::types::Image).
    pub fn build(self) -> crate::types::Image {
        crate::types::Image {
            id: self.id,
            file: self.file,
        }
    }
}
