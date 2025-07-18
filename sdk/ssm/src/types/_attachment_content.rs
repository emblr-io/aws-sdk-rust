// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that includes attributes that describe a document attachment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AttachmentContent {
    /// <p>The name of an attachment.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The size of an attachment in bytes.</p>
    pub size: i64,
    /// <p>The cryptographic hash value of the document content.</p>
    pub hash: ::std::option::Option<::std::string::String>,
    /// <p>The hash algorithm used to calculate the hash value.</p>
    pub hash_type: ::std::option::Option<crate::types::AttachmentHashType>,
    /// <p>The URL location of the attachment content.</p>
    pub url: ::std::option::Option<::std::string::String>,
}
impl AttachmentContent {
    /// <p>The name of an attachment.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The size of an attachment in bytes.</p>
    pub fn size(&self) -> i64 {
        self.size
    }
    /// <p>The cryptographic hash value of the document content.</p>
    pub fn hash(&self) -> ::std::option::Option<&str> {
        self.hash.as_deref()
    }
    /// <p>The hash algorithm used to calculate the hash value.</p>
    pub fn hash_type(&self) -> ::std::option::Option<&crate::types::AttachmentHashType> {
        self.hash_type.as_ref()
    }
    /// <p>The URL location of the attachment content.</p>
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
}
impl AttachmentContent {
    /// Creates a new builder-style object to manufacture [`AttachmentContent`](crate::types::AttachmentContent).
    pub fn builder() -> crate::types::builders::AttachmentContentBuilder {
        crate::types::builders::AttachmentContentBuilder::default()
    }
}

/// A builder for [`AttachmentContent`](crate::types::AttachmentContent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AttachmentContentBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) size: ::std::option::Option<i64>,
    pub(crate) hash: ::std::option::Option<::std::string::String>,
    pub(crate) hash_type: ::std::option::Option<crate::types::AttachmentHashType>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
}
impl AttachmentContentBuilder {
    /// <p>The name of an attachment.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of an attachment.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of an attachment.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The size of an attachment in bytes.</p>
    pub fn size(mut self, input: i64) -> Self {
        self.size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of an attachment in bytes.</p>
    pub fn set_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size = input;
        self
    }
    /// <p>The size of an attachment in bytes.</p>
    pub fn get_size(&self) -> &::std::option::Option<i64> {
        &self.size
    }
    /// <p>The cryptographic hash value of the document content.</p>
    pub fn hash(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hash = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cryptographic hash value of the document content.</p>
    pub fn set_hash(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hash = input;
        self
    }
    /// <p>The cryptographic hash value of the document content.</p>
    pub fn get_hash(&self) -> &::std::option::Option<::std::string::String> {
        &self.hash
    }
    /// <p>The hash algorithm used to calculate the hash value.</p>
    pub fn hash_type(mut self, input: crate::types::AttachmentHashType) -> Self {
        self.hash_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The hash algorithm used to calculate the hash value.</p>
    pub fn set_hash_type(mut self, input: ::std::option::Option<crate::types::AttachmentHashType>) -> Self {
        self.hash_type = input;
        self
    }
    /// <p>The hash algorithm used to calculate the hash value.</p>
    pub fn get_hash_type(&self) -> &::std::option::Option<crate::types::AttachmentHashType> {
        &self.hash_type
    }
    /// <p>The URL location of the attachment content.</p>
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL location of the attachment content.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>The URL location of the attachment content.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Consumes the builder and constructs a [`AttachmentContent`](crate::types::AttachmentContent).
    pub fn build(self) -> crate::types::AttachmentContent {
        crate::types::AttachmentContent {
            name: self.name,
            size: self.size.unwrap_or_default(),
            hash: self.hash,
            hash_type: self.hash_type,
            url: self.url,
        }
    }
}
