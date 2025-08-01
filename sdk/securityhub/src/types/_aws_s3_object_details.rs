// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about an Amazon S3 object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsS3ObjectDetails {
    /// <p>Indicates when the object was last modified.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub last_modified: ::std::option::Option<::std::string::String>,
    /// <p>The opaque identifier assigned by a web server to a specific version of a resource found at a URL.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    /// <p>The version of the object.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
    /// <p>A standard MIME type describing the format of the object data.</p>
    pub content_type: ::std::option::Option<::std::string::String>,
    /// <p>If the object is stored using server-side encryption, the value of the server-side encryption algorithm used when storing this object in Amazon S3.</p>
    pub server_side_encryption: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the KMS symmetric customer managed key that was used for the object.</p>
    pub ssekms_key_id: ::std::option::Option<::std::string::String>,
}
impl AwsS3ObjectDetails {
    /// <p>Indicates when the object was last modified.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn last_modified(&self) -> ::std::option::Option<&str> {
        self.last_modified.as_deref()
    }
    /// <p>The opaque identifier assigned by a web server to a specific version of a resource found at a URL.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
    /// <p>The version of the object.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
    /// <p>A standard MIME type describing the format of the object data.</p>
    pub fn content_type(&self) -> ::std::option::Option<&str> {
        self.content_type.as_deref()
    }
    /// <p>If the object is stored using server-side encryption, the value of the server-side encryption algorithm used when storing this object in Amazon S3.</p>
    pub fn server_side_encryption(&self) -> ::std::option::Option<&str> {
        self.server_side_encryption.as_deref()
    }
    /// <p>The identifier of the KMS symmetric customer managed key that was used for the object.</p>
    pub fn ssekms_key_id(&self) -> ::std::option::Option<&str> {
        self.ssekms_key_id.as_deref()
    }
}
impl AwsS3ObjectDetails {
    /// Creates a new builder-style object to manufacture [`AwsS3ObjectDetails`](crate::types::AwsS3ObjectDetails).
    pub fn builder() -> crate::types::builders::AwsS3ObjectDetailsBuilder {
        crate::types::builders::AwsS3ObjectDetailsBuilder::default()
    }
}

/// A builder for [`AwsS3ObjectDetails`](crate::types::AwsS3ObjectDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsS3ObjectDetailsBuilder {
    pub(crate) last_modified: ::std::option::Option<::std::string::String>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
    pub(crate) server_side_encryption: ::std::option::Option<::std::string::String>,
    pub(crate) ssekms_key_id: ::std::option::Option<::std::string::String>,
}
impl AwsS3ObjectDetailsBuilder {
    /// <p>Indicates when the object was last modified.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn last_modified(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates when the object was last modified.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn set_last_modified(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified = input;
        self
    }
    /// <p>Indicates when the object was last modified.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn get_last_modified(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified
    }
    /// <p>The opaque identifier assigned by a web server to a specific version of a resource found at a URL.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The opaque identifier assigned by a web server to a specific version of a resource found at a URL.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The opaque identifier assigned by a web server to a specific version of a resource found at a URL.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    /// <p>The version of the object.</p>
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the object.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>The version of the object.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// <p>A standard MIME type describing the format of the object data.</p>
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A standard MIME type describing the format of the object data.</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>A standard MIME type describing the format of the object data.</p>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// <p>If the object is stored using server-side encryption, the value of the server-side encryption algorithm used when storing this object in Amazon S3.</p>
    pub fn server_side_encryption(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_side_encryption = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the object is stored using server-side encryption, the value of the server-side encryption algorithm used when storing this object in Amazon S3.</p>
    pub fn set_server_side_encryption(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_side_encryption = input;
        self
    }
    /// <p>If the object is stored using server-side encryption, the value of the server-side encryption algorithm used when storing this object in Amazon S3.</p>
    pub fn get_server_side_encryption(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_side_encryption
    }
    /// <p>The identifier of the KMS symmetric customer managed key that was used for the object.</p>
    pub fn ssekms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ssekms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the KMS symmetric customer managed key that was used for the object.</p>
    pub fn set_ssekms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ssekms_key_id = input;
        self
    }
    /// <p>The identifier of the KMS symmetric customer managed key that was used for the object.</p>
    pub fn get_ssekms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ssekms_key_id
    }
    /// Consumes the builder and constructs a [`AwsS3ObjectDetails`](crate::types::AwsS3ObjectDetails).
    pub fn build(self) -> crate::types::AwsS3ObjectDetails {
        crate::types::AwsS3ObjectDetails {
            last_modified: self.last_modified,
            e_tag: self.e_tag,
            version_id: self.version_id,
            content_type: self.content_type,
            server_side_encryption: self.server_side_encryption,
            ssekms_key_id: self.ssekms_key_id,
        }
    }
}
