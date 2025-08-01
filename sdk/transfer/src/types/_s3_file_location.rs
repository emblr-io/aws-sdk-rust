// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the details for the file location for the file that's being used in the workflow. Only applicable if you are using S3 storage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3FileLocation {
    /// <p>Specifies the S3 bucket that contains the file being used.</p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>The name assigned to the file when it was created in Amazon S3. You use the object key to retrieve the object.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the file version.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
    /// <p>The entity tag is a hash of the object. The ETag reflects changes only to the contents of an object, not its metadata.</p>
    pub etag: ::std::option::Option<::std::string::String>,
}
impl S3FileLocation {
    /// <p>Specifies the S3 bucket that contains the file being used.</p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>The name assigned to the file when it was created in Amazon S3. You use the object key to retrieve the object.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>Specifies the file version.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
    /// <p>The entity tag is a hash of the object. The ETag reflects changes only to the contents of an object, not its metadata.</p>
    pub fn etag(&self) -> ::std::option::Option<&str> {
        self.etag.as_deref()
    }
}
impl S3FileLocation {
    /// Creates a new builder-style object to manufacture [`S3FileLocation`](crate::types::S3FileLocation).
    pub fn builder() -> crate::types::builders::S3FileLocationBuilder {
        crate::types::builders::S3FileLocationBuilder::default()
    }
}

/// A builder for [`S3FileLocation`](crate::types::S3FileLocation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3FileLocationBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
    pub(crate) etag: ::std::option::Option<::std::string::String>,
}
impl S3FileLocationBuilder {
    /// <p>Specifies the S3 bucket that contains the file being used.</p>
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the S3 bucket that contains the file being used.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>Specifies the S3 bucket that contains the file being used.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The name assigned to the file when it was created in Amazon S3. You use the object key to retrieve the object.</p>
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name assigned to the file when it was created in Amazon S3. You use the object key to retrieve the object.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The name assigned to the file when it was created in Amazon S3. You use the object key to retrieve the object.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>Specifies the file version.</p>
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the file version.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>Specifies the file version.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// <p>The entity tag is a hash of the object. The ETag reflects changes only to the contents of an object, not its metadata.</p>
    pub fn etag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.etag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The entity tag is a hash of the object. The ETag reflects changes only to the contents of an object, not its metadata.</p>
    pub fn set_etag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.etag = input;
        self
    }
    /// <p>The entity tag is a hash of the object. The ETag reflects changes only to the contents of an object, not its metadata.</p>
    pub fn get_etag(&self) -> &::std::option::Option<::std::string::String> {
        &self.etag
    }
    /// Consumes the builder and constructs a [`S3FileLocation`](crate::types::S3FileLocation).
    pub fn build(self) -> crate::types::S3FileLocation {
        crate::types::S3FileLocation {
            bucket: self.bucket,
            key: self.key,
            version_id: self.version_id,
            etag: self.etag,
        }
    }
}
