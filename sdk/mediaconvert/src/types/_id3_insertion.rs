// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// To insert ID3 tags in your output, specify two values. Use ID3 tag to specify the base 64 encoded string and use Timecode to specify the time when the tag should be inserted. To insert multiple ID3 tags in your output, create multiple instances of ID3 insertion.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Id3Insertion {
    /// Use ID3 tag to provide a fully formed ID3 tag in base64-encode format.
    pub id3: ::std::option::Option<::std::string::String>,
    /// Provide a Timecode in HH:MM:SS:FF or HH:MM:SS;FF format.
    pub timecode: ::std::option::Option<::std::string::String>,
}
impl Id3Insertion {
    /// Use ID3 tag to provide a fully formed ID3 tag in base64-encode format.
    pub fn id3(&self) -> ::std::option::Option<&str> {
        self.id3.as_deref()
    }
    /// Provide a Timecode in HH:MM:SS:FF or HH:MM:SS;FF format.
    pub fn timecode(&self) -> ::std::option::Option<&str> {
        self.timecode.as_deref()
    }
}
impl Id3Insertion {
    /// Creates a new builder-style object to manufacture [`Id3Insertion`](crate::types::Id3Insertion).
    pub fn builder() -> crate::types::builders::Id3InsertionBuilder {
        crate::types::builders::Id3InsertionBuilder::default()
    }
}

/// A builder for [`Id3Insertion`](crate::types::Id3Insertion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Id3InsertionBuilder {
    pub(crate) id3: ::std::option::Option<::std::string::String>,
    pub(crate) timecode: ::std::option::Option<::std::string::String>,
}
impl Id3InsertionBuilder {
    /// Use ID3 tag to provide a fully formed ID3 tag in base64-encode format.
    pub fn id3(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id3 = ::std::option::Option::Some(input.into());
        self
    }
    /// Use ID3 tag to provide a fully formed ID3 tag in base64-encode format.
    pub fn set_id3(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id3 = input;
        self
    }
    /// Use ID3 tag to provide a fully formed ID3 tag in base64-encode format.
    pub fn get_id3(&self) -> &::std::option::Option<::std::string::String> {
        &self.id3
    }
    /// Provide a Timecode in HH:MM:SS:FF or HH:MM:SS;FF format.
    pub fn timecode(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timecode = ::std::option::Option::Some(input.into());
        self
    }
    /// Provide a Timecode in HH:MM:SS:FF or HH:MM:SS;FF format.
    pub fn set_timecode(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timecode = input;
        self
    }
    /// Provide a Timecode in HH:MM:SS:FF or HH:MM:SS;FF format.
    pub fn get_timecode(&self) -> &::std::option::Option<::std::string::String> {
        &self.timecode
    }
    /// Consumes the builder and constructs a [`Id3Insertion`](crate::types::Id3Insertion).
    pub fn build(self) -> crate::types::Id3Insertion {
        crate::types::Id3Insertion {
            id3: self.id3,
            timecode: self.timecode,
        }
    }
}
