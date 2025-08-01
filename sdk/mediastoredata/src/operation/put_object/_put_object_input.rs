// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::fmt::Debug)]
pub struct PutObjectInput {
    /// <p>The bytes to be stored.</p>
    #[cfg_attr(any(feature = "serde-serialize", feature = "serde-deserialize"), serde(skip))]
    pub body: ::aws_smithy_types::byte_stream::ByteStream,
    /// <p>The path (including the file name) where the object is stored in the container. Format: <folder name>
    /// /
    /// <folder name>
    /// /
    /// <file name></file>
    /// </folder>
    /// </folder></p>
    /// <p>For example, to upload the file <code>mlaw.avi</code> to the folder path <code>premium\canada</code> in the container <code>movies</code>, enter the path <code>premium/canada/mlaw.avi</code>.</p>
    /// <p>Do not include the container name in this path.</p>
    /// <p>If the path includes any folders that don't exist yet, the service creates them. For example, suppose you have an existing <code>premium/usa</code> subfolder. If you specify <code>premium/canada</code>, the service creates a <code>canada</code> subfolder in the <code>premium</code> folder. You then have two subfolders, <code>usa</code> and <code>canada</code>, in the <code>premium</code> folder.</p>
    /// <p>There is no correlation between the path to the source and the path (folders) in the container in AWS Elemental MediaStore.</p>
    /// <p>For more information about folders and how they exist in a container, see the <a href="http://docs.aws.amazon.com/mediastore/latest/ug/">AWS Elemental MediaStore User Guide</a>.</p>
    /// <p>The file name is the name that is assigned to the file that you upload. The file can have the same name inside and outside of AWS Elemental MediaStore, or it can have the same name. The file name can include or omit an extension.</p>
    pub path: ::std::option::Option<::std::string::String>,
    /// <p>The content type of the object.</p>
    pub content_type: ::std::option::Option<::std::string::String>,
    /// <p>An optional <code>CacheControl</code> header that allows the caller to control the object's cache behavior. Headers can be passed in as specified in the HTTP at <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9">https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9</a>.</p>
    /// <p>Headers with a custom user-defined value are also accepted.</p>
    pub cache_control: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the storage class of a <code>Put</code> request. Defaults to high-performance temporal storage class, and objects are persisted into durable storage shortly after being received.</p>
    pub storage_class: ::std::option::Option<crate::types::StorageClass>,
    /// <p>Indicates the availability of an object while it is still uploading. If the value is set to <code>streaming</code>, the object is available for downloading after some initial buffering but before the object is uploaded completely. If the value is set to <code>standard</code>, the object is available for downloading only when it is uploaded completely. The default value for this header is <code>standard</code>.</p>
    /// <p>To use this header, you must also set the HTTP <code>Transfer-Encoding</code> header to <code>chunked</code>.</p>
    pub upload_availability: ::std::option::Option<crate::types::UploadAvailability>,
}
impl PutObjectInput {
    /// <p>The bytes to be stored.</p>
    pub fn body(&self) -> &::aws_smithy_types::byte_stream::ByteStream {
        &self.body
    }
    /// <p>The path (including the file name) where the object is stored in the container. Format: <folder name>
    /// /
    /// <folder name>
    /// /
    /// <file name></file>
    /// </folder>
    /// </folder></p>
    /// <p>For example, to upload the file <code>mlaw.avi</code> to the folder path <code>premium\canada</code> in the container <code>movies</code>, enter the path <code>premium/canada/mlaw.avi</code>.</p>
    /// <p>Do not include the container name in this path.</p>
    /// <p>If the path includes any folders that don't exist yet, the service creates them. For example, suppose you have an existing <code>premium/usa</code> subfolder. If you specify <code>premium/canada</code>, the service creates a <code>canada</code> subfolder in the <code>premium</code> folder. You then have two subfolders, <code>usa</code> and <code>canada</code>, in the <code>premium</code> folder.</p>
    /// <p>There is no correlation between the path to the source and the path (folders) in the container in AWS Elemental MediaStore.</p>
    /// <p>For more information about folders and how they exist in a container, see the <a href="http://docs.aws.amazon.com/mediastore/latest/ug/">AWS Elemental MediaStore User Guide</a>.</p>
    /// <p>The file name is the name that is assigned to the file that you upload. The file can have the same name inside and outside of AWS Elemental MediaStore, or it can have the same name. The file name can include or omit an extension.</p>
    pub fn path(&self) -> ::std::option::Option<&str> {
        self.path.as_deref()
    }
    /// <p>The content type of the object.</p>
    pub fn content_type(&self) -> ::std::option::Option<&str> {
        self.content_type.as_deref()
    }
    /// <p>An optional <code>CacheControl</code> header that allows the caller to control the object's cache behavior. Headers can be passed in as specified in the HTTP at <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9">https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9</a>.</p>
    /// <p>Headers with a custom user-defined value are also accepted.</p>
    pub fn cache_control(&self) -> ::std::option::Option<&str> {
        self.cache_control.as_deref()
    }
    /// <p>Indicates the storage class of a <code>Put</code> request. Defaults to high-performance temporal storage class, and objects are persisted into durable storage shortly after being received.</p>
    pub fn storage_class(&self) -> ::std::option::Option<&crate::types::StorageClass> {
        self.storage_class.as_ref()
    }
    /// <p>Indicates the availability of an object while it is still uploading. If the value is set to <code>streaming</code>, the object is available for downloading after some initial buffering but before the object is uploaded completely. If the value is set to <code>standard</code>, the object is available for downloading only when it is uploaded completely. The default value for this header is <code>standard</code>.</p>
    /// <p>To use this header, you must also set the HTTP <code>Transfer-Encoding</code> header to <code>chunked</code>.</p>
    pub fn upload_availability(&self) -> ::std::option::Option<&crate::types::UploadAvailability> {
        self.upload_availability.as_ref()
    }
}
impl PutObjectInput {
    /// Creates a new builder-style object to manufacture [`PutObjectInput`](crate::operation::put_object::PutObjectInput).
    pub fn builder() -> crate::operation::put_object::builders::PutObjectInputBuilder {
        crate::operation::put_object::builders::PutObjectInputBuilder::default()
    }
}

/// A builder for [`PutObjectInput`](crate::operation::put_object::PutObjectInput).
#[derive(::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutObjectInputBuilder {
    pub(crate) body: ::std::option::Option<::aws_smithy_types::byte_stream::ByteStream>,
    pub(crate) path: ::std::option::Option<::std::string::String>,
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
    pub(crate) cache_control: ::std::option::Option<::std::string::String>,
    pub(crate) storage_class: ::std::option::Option<crate::types::StorageClass>,
    pub(crate) upload_availability: ::std::option::Option<crate::types::UploadAvailability>,
}
impl PutObjectInputBuilder {
    /// <p>The bytes to be stored.</p>
    /// This field is required.
    pub fn body(mut self, input: ::aws_smithy_types::byte_stream::ByteStream) -> Self {
        self.body = ::std::option::Option::Some(input);
        self
    }
    /// <p>The bytes to be stored.</p>
    pub fn set_body(mut self, input: ::std::option::Option<::aws_smithy_types::byte_stream::ByteStream>) -> Self {
        self.body = input;
        self
    }
    /// <p>The bytes to be stored.</p>
    pub fn get_body(&self) -> &::std::option::Option<::aws_smithy_types::byte_stream::ByteStream> {
        &self.body
    }
    /// <p>The path (including the file name) where the object is stored in the container. Format: <folder name>
    /// /
    /// <folder name>
    /// /
    /// <file name></file>
    /// </folder>
    /// </folder></p>
    /// <p>For example, to upload the file <code>mlaw.avi</code> to the folder path <code>premium\canada</code> in the container <code>movies</code>, enter the path <code>premium/canada/mlaw.avi</code>.</p>
    /// <p>Do not include the container name in this path.</p>
    /// <p>If the path includes any folders that don't exist yet, the service creates them. For example, suppose you have an existing <code>premium/usa</code> subfolder. If you specify <code>premium/canada</code>, the service creates a <code>canada</code> subfolder in the <code>premium</code> folder. You then have two subfolders, <code>usa</code> and <code>canada</code>, in the <code>premium</code> folder.</p>
    /// <p>There is no correlation between the path to the source and the path (folders) in the container in AWS Elemental MediaStore.</p>
    /// <p>For more information about folders and how they exist in a container, see the <a href="http://docs.aws.amazon.com/mediastore/latest/ug/">AWS Elemental MediaStore User Guide</a>.</p>
    /// <p>The file name is the name that is assigned to the file that you upload. The file can have the same name inside and outside of AWS Elemental MediaStore, or it can have the same name. The file name can include or omit an extension.</p>
    /// This field is required.
    pub fn path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path (including the file name) where the object is stored in the container. Format: <folder name>
    /// /
    /// <folder name>
    /// /
    /// <file name></file>
    /// </folder>
    /// </folder></p>
    /// <p>For example, to upload the file <code>mlaw.avi</code> to the folder path <code>premium\canada</code> in the container <code>movies</code>, enter the path <code>premium/canada/mlaw.avi</code>.</p>
    /// <p>Do not include the container name in this path.</p>
    /// <p>If the path includes any folders that don't exist yet, the service creates them. For example, suppose you have an existing <code>premium/usa</code> subfolder. If you specify <code>premium/canada</code>, the service creates a <code>canada</code> subfolder in the <code>premium</code> folder. You then have two subfolders, <code>usa</code> and <code>canada</code>, in the <code>premium</code> folder.</p>
    /// <p>There is no correlation between the path to the source and the path (folders) in the container in AWS Elemental MediaStore.</p>
    /// <p>For more information about folders and how they exist in a container, see the <a href="http://docs.aws.amazon.com/mediastore/latest/ug/">AWS Elemental MediaStore User Guide</a>.</p>
    /// <p>The file name is the name that is assigned to the file that you upload. The file can have the same name inside and outside of AWS Elemental MediaStore, or it can have the same name. The file name can include or omit an extension.</p>
    pub fn set_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path = input;
        self
    }
    /// <p>The path (including the file name) where the object is stored in the container. Format: <folder name>
    /// /
    /// <folder name>
    /// /
    /// <file name></file>
    /// </folder>
    /// </folder></p>
    /// <p>For example, to upload the file <code>mlaw.avi</code> to the folder path <code>premium\canada</code> in the container <code>movies</code>, enter the path <code>premium/canada/mlaw.avi</code>.</p>
    /// <p>Do not include the container name in this path.</p>
    /// <p>If the path includes any folders that don't exist yet, the service creates them. For example, suppose you have an existing <code>premium/usa</code> subfolder. If you specify <code>premium/canada</code>, the service creates a <code>canada</code> subfolder in the <code>premium</code> folder. You then have two subfolders, <code>usa</code> and <code>canada</code>, in the <code>premium</code> folder.</p>
    /// <p>There is no correlation between the path to the source and the path (folders) in the container in AWS Elemental MediaStore.</p>
    /// <p>For more information about folders and how they exist in a container, see the <a href="http://docs.aws.amazon.com/mediastore/latest/ug/">AWS Elemental MediaStore User Guide</a>.</p>
    /// <p>The file name is the name that is assigned to the file that you upload. The file can have the same name inside and outside of AWS Elemental MediaStore, or it can have the same name. The file name can include or omit an extension.</p>
    pub fn get_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.path
    }
    /// <p>The content type of the object.</p>
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content type of the object.</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>The content type of the object.</p>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// <p>An optional <code>CacheControl</code> header that allows the caller to control the object's cache behavior. Headers can be passed in as specified in the HTTP at <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9">https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9</a>.</p>
    /// <p>Headers with a custom user-defined value are also accepted.</p>
    pub fn cache_control(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cache_control = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional <code>CacheControl</code> header that allows the caller to control the object's cache behavior. Headers can be passed in as specified in the HTTP at <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9">https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9</a>.</p>
    /// <p>Headers with a custom user-defined value are also accepted.</p>
    pub fn set_cache_control(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cache_control = input;
        self
    }
    /// <p>An optional <code>CacheControl</code> header that allows the caller to control the object's cache behavior. Headers can be passed in as specified in the HTTP at <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9">https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9</a>.</p>
    /// <p>Headers with a custom user-defined value are also accepted.</p>
    pub fn get_cache_control(&self) -> &::std::option::Option<::std::string::String> {
        &self.cache_control
    }
    /// <p>Indicates the storage class of a <code>Put</code> request. Defaults to high-performance temporal storage class, and objects are persisted into durable storage shortly after being received.</p>
    pub fn storage_class(mut self, input: crate::types::StorageClass) -> Self {
        self.storage_class = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the storage class of a <code>Put</code> request. Defaults to high-performance temporal storage class, and objects are persisted into durable storage shortly after being received.</p>
    pub fn set_storage_class(mut self, input: ::std::option::Option<crate::types::StorageClass>) -> Self {
        self.storage_class = input;
        self
    }
    /// <p>Indicates the storage class of a <code>Put</code> request. Defaults to high-performance temporal storage class, and objects are persisted into durable storage shortly after being received.</p>
    pub fn get_storage_class(&self) -> &::std::option::Option<crate::types::StorageClass> {
        &self.storage_class
    }
    /// <p>Indicates the availability of an object while it is still uploading. If the value is set to <code>streaming</code>, the object is available for downloading after some initial buffering but before the object is uploaded completely. If the value is set to <code>standard</code>, the object is available for downloading only when it is uploaded completely. The default value for this header is <code>standard</code>.</p>
    /// <p>To use this header, you must also set the HTTP <code>Transfer-Encoding</code> header to <code>chunked</code>.</p>
    pub fn upload_availability(mut self, input: crate::types::UploadAvailability) -> Self {
        self.upload_availability = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the availability of an object while it is still uploading. If the value is set to <code>streaming</code>, the object is available for downloading after some initial buffering but before the object is uploaded completely. If the value is set to <code>standard</code>, the object is available for downloading only when it is uploaded completely. The default value for this header is <code>standard</code>.</p>
    /// <p>To use this header, you must also set the HTTP <code>Transfer-Encoding</code> header to <code>chunked</code>.</p>
    pub fn set_upload_availability(mut self, input: ::std::option::Option<crate::types::UploadAvailability>) -> Self {
        self.upload_availability = input;
        self
    }
    /// <p>Indicates the availability of an object while it is still uploading. If the value is set to <code>streaming</code>, the object is available for downloading after some initial buffering but before the object is uploaded completely. If the value is set to <code>standard</code>, the object is available for downloading only when it is uploaded completely. The default value for this header is <code>standard</code>.</p>
    /// <p>To use this header, you must also set the HTTP <code>Transfer-Encoding</code> header to <code>chunked</code>.</p>
    pub fn get_upload_availability(&self) -> &::std::option::Option<crate::types::UploadAvailability> {
        &self.upload_availability
    }
    /// Consumes the builder and constructs a [`PutObjectInput`](crate::operation::put_object::PutObjectInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::put_object::PutObjectInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_object::PutObjectInput {
            body: self.body.unwrap_or_default(),
            path: self.path,
            content_type: self.content_type,
            cache_control: self.cache_control,
            storage_class: self.storage_class,
            upload_availability: self.upload_availability,
        })
    }
}
