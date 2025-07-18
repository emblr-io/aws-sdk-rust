// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a disk image.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DiskImageDescription {
    /// <p>The checksum computed for the disk image.</p>
    pub checksum: ::std::option::Option<::std::string::String>,
    /// <p>The disk image format.</p>
    pub format: ::std::option::Option<crate::types::DiskImageFormat>,
    /// <p>A presigned URL for the import manifest stored in Amazon S3. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    pub import_manifest_url: ::std::option::Option<::std::string::String>,
    /// <p>The size of the disk image, in GiB.</p>
    pub size: ::std::option::Option<i64>,
}
impl DiskImageDescription {
    /// <p>The checksum computed for the disk image.</p>
    pub fn checksum(&self) -> ::std::option::Option<&str> {
        self.checksum.as_deref()
    }
    /// <p>The disk image format.</p>
    pub fn format(&self) -> ::std::option::Option<&crate::types::DiskImageFormat> {
        self.format.as_ref()
    }
    /// <p>A presigned URL for the import manifest stored in Amazon S3. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    pub fn import_manifest_url(&self) -> ::std::option::Option<&str> {
        self.import_manifest_url.as_deref()
    }
    /// <p>The size of the disk image, in GiB.</p>
    pub fn size(&self) -> ::std::option::Option<i64> {
        self.size
    }
}
impl ::std::fmt::Debug for DiskImageDescription {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DiskImageDescription");
        formatter.field("checksum", &self.checksum);
        formatter.field("format", &self.format);
        formatter.field("import_manifest_url", &"*** Sensitive Data Redacted ***");
        formatter.field("size", &self.size);
        formatter.finish()
    }
}
impl DiskImageDescription {
    /// Creates a new builder-style object to manufacture [`DiskImageDescription`](crate::types::DiskImageDescription).
    pub fn builder() -> crate::types::builders::DiskImageDescriptionBuilder {
        crate::types::builders::DiskImageDescriptionBuilder::default()
    }
}

/// A builder for [`DiskImageDescription`](crate::types::DiskImageDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DiskImageDescriptionBuilder {
    pub(crate) checksum: ::std::option::Option<::std::string::String>,
    pub(crate) format: ::std::option::Option<crate::types::DiskImageFormat>,
    pub(crate) import_manifest_url: ::std::option::Option<::std::string::String>,
    pub(crate) size: ::std::option::Option<i64>,
}
impl DiskImageDescriptionBuilder {
    /// <p>The checksum computed for the disk image.</p>
    pub fn checksum(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.checksum = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The checksum computed for the disk image.</p>
    pub fn set_checksum(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.checksum = input;
        self
    }
    /// <p>The checksum computed for the disk image.</p>
    pub fn get_checksum(&self) -> &::std::option::Option<::std::string::String> {
        &self.checksum
    }
    /// <p>The disk image format.</p>
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
    /// <p>A presigned URL for the import manifest stored in Amazon S3. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    pub fn import_manifest_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.import_manifest_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A presigned URL for the import manifest stored in Amazon S3. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    pub fn set_import_manifest_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.import_manifest_url = input;
        self
    }
    /// <p>A presigned URL for the import manifest stored in Amazon S3. For information about creating a presigned URL for an Amazon S3 object, read the "Query String Request Authentication Alternative" section of the <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html">Authenticating REST Requests</a> topic in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    /// <p>For information about the import manifest referenced by this API action, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html">VM Import Manifest</a>.</p>
    pub fn get_import_manifest_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.import_manifest_url
    }
    /// <p>The size of the disk image, in GiB.</p>
    pub fn size(mut self, input: i64) -> Self {
        self.size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the disk image, in GiB.</p>
    pub fn set_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size = input;
        self
    }
    /// <p>The size of the disk image, in GiB.</p>
    pub fn get_size(&self) -> &::std::option::Option<i64> {
        &self.size
    }
    /// Consumes the builder and constructs a [`DiskImageDescription`](crate::types::DiskImageDescription).
    pub fn build(self) -> crate::types::DiskImageDescription {
        crate::types::DiskImageDescription {
            checksum: self.checksum,
            format: self.format,
            import_manifest_url: self.import_manifest_url,
            size: self.size,
        }
    }
}
impl ::std::fmt::Debug for DiskImageDescriptionBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DiskImageDescriptionBuilder");
        formatter.field("checksum", &self.checksum);
        formatter.field("format", &self.format);
        formatter.field("import_manifest_url", &"*** Sensitive Data Redacted ***");
        formatter.field("size", &self.size);
        formatter.finish()
    }
}
