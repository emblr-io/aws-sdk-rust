// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a disk image.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DiskImageDetail {
    /// <p>The disk image format.</p>
    pub format: ::std::option::Option<crate::types::DiskImageFormat>,
    /// <p>The size of the disk image, in GiB.</p>
    pub bytes: ::std::option::Option<i64>,
    /// <p>A presigned URL for the import manifest stored in Amazon S3 and presented here as an Amazon S3 presigned URL. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    pub import_manifest_url: ::std::option::Option<::std::string::String>,
}
impl DiskImageDetail {
    /// <p>The disk image format.</p>
    pub fn format(&self) -> ::std::option::Option<&crate::types::DiskImageFormat> {
        self.format.as_ref()
    }
    /// <p>The size of the disk image, in GiB.</p>
    pub fn bytes(&self) -> ::std::option::Option<i64> {
        self.bytes
    }
    /// <p>A presigned URL for the import manifest stored in Amazon S3 and presented here as an Amazon S3 presigned URL. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    pub fn import_manifest_url(&self) -> ::std::option::Option<&str> {
        self.import_manifest_url.as_deref()
    }
}
impl ::std::fmt::Debug for DiskImageDetail {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DiskImageDetail");
        formatter.field("format", &self.format);
        formatter.field("bytes", &self.bytes);
        formatter.field("import_manifest_url", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl DiskImageDetail {
    /// Creates a new builder-style object to manufacture [`DiskImageDetail`](crate::types::DiskImageDetail).
    pub fn builder() -> crate::types::builders::DiskImageDetailBuilder {
        crate::types::builders::DiskImageDetailBuilder::default()
    }
}

/// A builder for [`DiskImageDetail`](crate::types::DiskImageDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DiskImageDetailBuilder {
    pub(crate) format: ::std::option::Option<crate::types::DiskImageFormat>,
    pub(crate) bytes: ::std::option::Option<i64>,
    pub(crate) import_manifest_url: ::std::option::Option<::std::string::String>,
}
impl DiskImageDetailBuilder {
    /// <p>The disk image format.</p>
    /// This field is required.
    pub fn format(mut self, input: crate::types::DiskImageFormat) -> Self {
        self.format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The disk image format.</p>
    pub fn set_format(mut self, input: ::std::option::Option<crate::types::DiskImageFormat>) -> Self {
        self.format = input;
        self
    }
    /// <p>The disk image format.</p>
    pub fn get_format(&self) -> &::std::option::Option<crate::types::DiskImageFormat> {
        &self.format
    }
    /// <p>The size of the disk image, in GiB.</p>
    /// This field is required.
    pub fn bytes(mut self, input: i64) -> Self {
        self.bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the disk image, in GiB.</p>
    pub fn set_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.bytes = input;
        self
    }
    /// <p>The size of the disk image, in GiB.</p>
    pub fn get_bytes(&self) -> &::std::option::Option<i64> {
        &self.bytes
    }
    /// <p>A presigned URL for the import manifest stored in Amazon S3 and presented here as an Amazon S3 presigned URL. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    /// This field is required.
    pub fn import_manifest_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.import_manifest_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A presigned URL for the import manifest stored in Amazon S3 and presented here as an Amazon S3 presigned URL. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    pub fn set_import_manifest_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.import_manifest_url = input;
        self
    }
    /// <p>A presigned URL for the import manifest stored in Amazon S3 and presented here as an Amazon S3 presigned URL. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    pub fn get_import_manifest_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.import_manifest_url
    }
    /// Consumes the builder and constructs a [`DiskImageDetail`](crate::types::DiskImageDetail).
    pub fn build(self) -> crate::types::DiskImageDetail {
        crate::types::DiskImageDetail {
            format: self.format,
            bytes: self.bytes,
            import_manifest_url: self.import_manifest_url,
        }
    }
}
impl ::std::fmt::Debug for DiskImageDetailBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DiskImageDetailBuilder");
        formatter.field("format", &self.format);
        formatter.field("bytes", &self.bytes);
        formatter.field("import_manifest_url", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
