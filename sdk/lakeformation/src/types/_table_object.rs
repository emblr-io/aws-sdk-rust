// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the details of a governed table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TableObject {
    /// <p>The Amazon S3 location of the object.</p>
    pub uri: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon S3 ETag of the object. Returned by <code>GetTableObjects</code> for validation and used to identify changes to the underlying data.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    /// <p>The size of the Amazon S3 object in bytes.</p>
    pub size: i64,
}
impl TableObject {
    /// <p>The Amazon S3 location of the object.</p>
    pub fn uri(&self) -> ::std::option::Option<&str> {
        self.uri.as_deref()
    }
    /// <p>The Amazon S3 ETag of the object. Returned by <code>GetTableObjects</code> for validation and used to identify changes to the underlying data.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
    /// <p>The size of the Amazon S3 object in bytes.</p>
    pub fn size(&self) -> i64 {
        self.size
    }
}
impl TableObject {
    /// Creates a new builder-style object to manufacture [`TableObject`](crate::types::TableObject).
    pub fn builder() -> crate::types::builders::TableObjectBuilder {
        crate::types::builders::TableObjectBuilder::default()
    }
}

/// A builder for [`TableObject`](crate::types::TableObject).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TableObjectBuilder {
    pub(crate) uri: ::std::option::Option<::std::string::String>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    pub(crate) size: ::std::option::Option<i64>,
}
impl TableObjectBuilder {
    /// <p>The Amazon S3 location of the object.</p>
    pub fn uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 location of the object.</p>
    pub fn set_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.uri = input;
        self
    }
    /// <p>The Amazon S3 location of the object.</p>
    pub fn get_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.uri
    }
    /// <p>The Amazon S3 ETag of the object. Returned by <code>GetTableObjects</code> for validation and used to identify changes to the underlying data.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 ETag of the object. Returned by <code>GetTableObjects</code> for validation and used to identify changes to the underlying data.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The Amazon S3 ETag of the object. Returned by <code>GetTableObjects</code> for validation and used to identify changes to the underlying data.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    /// <p>The size of the Amazon S3 object in bytes.</p>
    pub fn size(mut self, input: i64) -> Self {
        self.size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the Amazon S3 object in bytes.</p>
    pub fn set_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size = input;
        self
    }
    /// <p>The size of the Amazon S3 object in bytes.</p>
    pub fn get_size(&self) -> &::std::option::Option<i64> {
        &self.size
    }
    /// Consumes the builder and constructs a [`TableObject`](crate::types::TableObject).
    pub fn build(self) -> crate::types::TableObject {
        crate::types::TableObject {
            uri: self.uri,
            e_tag: self.e_tag,
            size: self.size.unwrap_or_default(),
        }
    }
}
