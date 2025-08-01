// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a celebrity recognized by the <code>RecognizeCelebrities</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Celebrity {
    /// <p>An array of URLs pointing to additional information about the celebrity. If there is no additional information about the celebrity, this list is empty.</p>
    pub urls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the celebrity.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the celebrity.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>Provides information about the celebrity's face, such as its location on the image.</p>
    pub face: ::std::option::Option<crate::types::ComparedFace>,
    /// <p>The confidence, in percentage, that Amazon Rekognition has that the recognized face is the celebrity.</p>
    pub match_confidence: ::std::option::Option<f32>,
    /// <p>The known gender identity for the celebrity that matches the provided ID. The known gender identity can be Male, Female, Nonbinary, or Unlisted.</p>
    pub known_gender: ::std::option::Option<crate::types::KnownGender>,
}
impl Celebrity {
    /// <p>An array of URLs pointing to additional information about the celebrity. If there is no additional information about the celebrity, this list is empty.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.urls.is_none()`.
    pub fn urls(&self) -> &[::std::string::String] {
        self.urls.as_deref().unwrap_or_default()
    }
    /// <p>The name of the celebrity.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A unique identifier for the celebrity.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>Provides information about the celebrity's face, such as its location on the image.</p>
    pub fn face(&self) -> ::std::option::Option<&crate::types::ComparedFace> {
        self.face.as_ref()
    }
    /// <p>The confidence, in percentage, that Amazon Rekognition has that the recognized face is the celebrity.</p>
    pub fn match_confidence(&self) -> ::std::option::Option<f32> {
        self.match_confidence
    }
    /// <p>The known gender identity for the celebrity that matches the provided ID. The known gender identity can be Male, Female, Nonbinary, or Unlisted.</p>
    pub fn known_gender(&self) -> ::std::option::Option<&crate::types::KnownGender> {
        self.known_gender.as_ref()
    }
}
impl Celebrity {
    /// Creates a new builder-style object to manufacture [`Celebrity`](crate::types::Celebrity).
    pub fn builder() -> crate::types::builders::CelebrityBuilder {
        crate::types::builders::CelebrityBuilder::default()
    }
}

/// A builder for [`Celebrity`](crate::types::Celebrity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CelebrityBuilder {
    pub(crate) urls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) face: ::std::option::Option<crate::types::ComparedFace>,
    pub(crate) match_confidence: ::std::option::Option<f32>,
    pub(crate) known_gender: ::std::option::Option<crate::types::KnownGender>,
}
impl CelebrityBuilder {
    /// Appends an item to `urls`.
    ///
    /// To override the contents of this collection use [`set_urls`](Self::set_urls).
    ///
    /// <p>An array of URLs pointing to additional information about the celebrity. If there is no additional information about the celebrity, this list is empty.</p>
    pub fn urls(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.urls.unwrap_or_default();
        v.push(input.into());
        self.urls = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of URLs pointing to additional information about the celebrity. If there is no additional information about the celebrity, this list is empty.</p>
    pub fn set_urls(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.urls = input;
        self
    }
    /// <p>An array of URLs pointing to additional information about the celebrity. If there is no additional information about the celebrity, this list is empty.</p>
    pub fn get_urls(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.urls
    }
    /// <p>The name of the celebrity.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the celebrity.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the celebrity.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A unique identifier for the celebrity.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the celebrity.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>A unique identifier for the celebrity.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Provides information about the celebrity's face, such as its location on the image.</p>
    pub fn face(mut self, input: crate::types::ComparedFace) -> Self {
        self.face = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about the celebrity's face, such as its location on the image.</p>
    pub fn set_face(mut self, input: ::std::option::Option<crate::types::ComparedFace>) -> Self {
        self.face = input;
        self
    }
    /// <p>Provides information about the celebrity's face, such as its location on the image.</p>
    pub fn get_face(&self) -> &::std::option::Option<crate::types::ComparedFace> {
        &self.face
    }
    /// <p>The confidence, in percentage, that Amazon Rekognition has that the recognized face is the celebrity.</p>
    pub fn match_confidence(mut self, input: f32) -> Self {
        self.match_confidence = ::std::option::Option::Some(input);
        self
    }
    /// <p>The confidence, in percentage, that Amazon Rekognition has that the recognized face is the celebrity.</p>
    pub fn set_match_confidence(mut self, input: ::std::option::Option<f32>) -> Self {
        self.match_confidence = input;
        self
    }
    /// <p>The confidence, in percentage, that Amazon Rekognition has that the recognized face is the celebrity.</p>
    pub fn get_match_confidence(&self) -> &::std::option::Option<f32> {
        &self.match_confidence
    }
    /// <p>The known gender identity for the celebrity that matches the provided ID. The known gender identity can be Male, Female, Nonbinary, or Unlisted.</p>
    pub fn known_gender(mut self, input: crate::types::KnownGender) -> Self {
        self.known_gender = ::std::option::Option::Some(input);
        self
    }
    /// <p>The known gender identity for the celebrity that matches the provided ID. The known gender identity can be Male, Female, Nonbinary, or Unlisted.</p>
    pub fn set_known_gender(mut self, input: ::std::option::Option<crate::types::KnownGender>) -> Self {
        self.known_gender = input;
        self
    }
    /// <p>The known gender identity for the celebrity that matches the provided ID. The known gender identity can be Male, Female, Nonbinary, or Unlisted.</p>
    pub fn get_known_gender(&self) -> &::std::option::Option<crate::types::KnownGender> {
        &self.known_gender
    }
    /// Consumes the builder and constructs a [`Celebrity`](crate::types::Celebrity).
    pub fn build(self) -> crate::types::Celebrity {
        crate::types::Celebrity {
            urls: self.urls,
            name: self.name,
            id: self.id,
            face: self.face,
            match_confidence: self.match_confidence,
            known_gender: self.known_gender,
        }
    }
}
