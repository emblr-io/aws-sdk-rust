// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutObjectOutput {
    /// <p>The SHA256 digest of the object that is persisted.</p>
    pub content_sha256: ::std::option::Option<::std::string::String>,
    /// <p>Unique identifier of the object in the container.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    /// <p>The storage class where the object was persisted. The class should be “Temporal”.</p>
    pub storage_class: ::std::option::Option<crate::types::StorageClass>,
    _request_id: Option<String>,
}
impl PutObjectOutput {
    /// <p>The SHA256 digest of the object that is persisted.</p>
    pub fn content_sha256(&self) -> ::std::option::Option<&str> {
        self.content_sha256.as_deref()
    }
    /// <p>Unique identifier of the object in the container.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
    /// <p>The storage class where the object was persisted. The class should be “Temporal”.</p>
    pub fn storage_class(&self) -> ::std::option::Option<&crate::types::StorageClass> {
        self.storage_class.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutObjectOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutObjectOutput {
    /// Creates a new builder-style object to manufacture [`PutObjectOutput`](crate::operation::put_object::PutObjectOutput).
    pub fn builder() -> crate::operation::put_object::builders::PutObjectOutputBuilder {
        crate::operation::put_object::builders::PutObjectOutputBuilder::default()
    }
}

/// A builder for [`PutObjectOutput`](crate::operation::put_object::PutObjectOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutObjectOutputBuilder {
    pub(crate) content_sha256: ::std::option::Option<::std::string::String>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    pub(crate) storage_class: ::std::option::Option<crate::types::StorageClass>,
    _request_id: Option<String>,
}
impl PutObjectOutputBuilder {
    /// <p>The SHA256 digest of the object that is persisted.</p>
    pub fn content_sha256(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_sha256 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SHA256 digest of the object that is persisted.</p>
    pub fn set_content_sha256(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_sha256 = input;
        self
    }
    /// <p>The SHA256 digest of the object that is persisted.</p>
    pub fn get_content_sha256(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_sha256
    }
    /// <p>Unique identifier of the object in the container.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier of the object in the container.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>Unique identifier of the object in the container.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    /// <p>The storage class where the object was persisted. The class should be “Temporal”.</p>
    pub fn storage_class(mut self, input: crate::types::StorageClass) -> Self {
        self.storage_class = ::std::option::Option::Some(input);
        self
    }
    /// <p>The storage class where the object was persisted. The class should be “Temporal”.</p>
    pub fn set_storage_class(mut self, input: ::std::option::Option<crate::types::StorageClass>) -> Self {
        self.storage_class = input;
        self
    }
    /// <p>The storage class where the object was persisted. The class should be “Temporal”.</p>
    pub fn get_storage_class(&self) -> &::std::option::Option<crate::types::StorageClass> {
        &self.storage_class
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutObjectOutput`](crate::operation::put_object::PutObjectOutput).
    pub fn build(self) -> crate::operation::put_object::PutObjectOutput {
        crate::operation::put_object::PutObjectOutput {
            content_sha256: self.content_sha256,
            e_tag: self.e_tag,
            storage_class: self.storage_class,
            _request_id: self._request_id,
        }
    }
}
