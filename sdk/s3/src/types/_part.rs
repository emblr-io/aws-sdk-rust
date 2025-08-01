// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for elements related to a part.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Part {
    /// <p>Part number identifying the part. This is a positive integer between 1 and 10,000.</p>
    pub part_number: ::std::option::Option<i32>,
    /// <p>Date and time at which the part was uploaded.</p>
    pub last_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Entity tag returned when the part was uploaded.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    /// <p>Size in bytes of the uploaded part data.</p>
    pub size: ::std::option::Option<i64>,
    /// <p>The Base64 encoded, 32-bit <code>CRC32</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub checksum_crc32: ::std::option::Option<::std::string::String>,
    /// <p>The Base64 encoded, 32-bit <code>CRC32C</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32C</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub checksum_crc32_c: ::std::option::Option<::std::string::String>,
    /// <p>The Base64 encoded, 64-bit <code>CRC64NVME</code> checksum of the part. This checksum is present if the multipart upload request was created with the <code>CRC64NVME</code> checksum algorithm, or if the object was uploaded without a checksum (and Amazon S3 added the default checksum, <code>CRC64NVME</code>, to the uploaded object). For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub checksum_crc64_nvme: ::std::option::Option<::std::string::String>,
    /// <p>The Base64 encoded, 160-bit <code>SHA1</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA1</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub checksum_sha1: ::std::option::Option<::std::string::String>,
    /// <p>The Base64 encoded, 256-bit <code>SHA256</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA256</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub checksum_sha256: ::std::option::Option<::std::string::String>,
}
impl Part {
    /// <p>Part number identifying the part. This is a positive integer between 1 and 10,000.</p>
    pub fn part_number(&self) -> ::std::option::Option<i32> {
        self.part_number
    }
    /// <p>Date and time at which the part was uploaded.</p>
    pub fn last_modified(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified.as_ref()
    }
    /// <p>Entity tag returned when the part was uploaded.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
    /// <p>Size in bytes of the uploaded part data.</p>
    pub fn size(&self) -> ::std::option::Option<i64> {
        self.size
    }
    /// <p>The Base64 encoded, 32-bit <code>CRC32</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_crc32(&self) -> ::std::option::Option<&str> {
        self.checksum_crc32.as_deref()
    }
    /// <p>The Base64 encoded, 32-bit <code>CRC32C</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32C</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_crc32_c(&self) -> ::std::option::Option<&str> {
        self.checksum_crc32_c.as_deref()
    }
    /// <p>The Base64 encoded, 64-bit <code>CRC64NVME</code> checksum of the part. This checksum is present if the multipart upload request was created with the <code>CRC64NVME</code> checksum algorithm, or if the object was uploaded without a checksum (and Amazon S3 added the default checksum, <code>CRC64NVME</code>, to the uploaded object). For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_crc64_nvme(&self) -> ::std::option::Option<&str> {
        self.checksum_crc64_nvme.as_deref()
    }
    /// <p>The Base64 encoded, 160-bit <code>SHA1</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA1</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_sha1(&self) -> ::std::option::Option<&str> {
        self.checksum_sha1.as_deref()
    }
    /// <p>The Base64 encoded, 256-bit <code>SHA256</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA256</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_sha256(&self) -> ::std::option::Option<&str> {
        self.checksum_sha256.as_deref()
    }
}
impl Part {
    /// Creates a new builder-style object to manufacture [`Part`](crate::types::Part).
    pub fn builder() -> crate::types::builders::PartBuilder {
        crate::types::builders::PartBuilder::default()
    }
}

/// A builder for [`Part`](crate::types::Part).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PartBuilder {
    pub(crate) part_number: ::std::option::Option<i32>,
    pub(crate) last_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    pub(crate) size: ::std::option::Option<i64>,
    pub(crate) checksum_crc32: ::std::option::Option<::std::string::String>,
    pub(crate) checksum_crc32_c: ::std::option::Option<::std::string::String>,
    pub(crate) checksum_crc64_nvme: ::std::option::Option<::std::string::String>,
    pub(crate) checksum_sha1: ::std::option::Option<::std::string::String>,
    pub(crate) checksum_sha256: ::std::option::Option<::std::string::String>,
}
impl PartBuilder {
    /// <p>Part number identifying the part. This is a positive integer between 1 and 10,000.</p>
    pub fn part_number(mut self, input: i32) -> Self {
        self.part_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>Part number identifying the part. This is a positive integer between 1 and 10,000.</p>
    pub fn set_part_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.part_number = input;
        self
    }
    /// <p>Part number identifying the part. This is a positive integer between 1 and 10,000.</p>
    pub fn get_part_number(&self) -> &::std::option::Option<i32> {
        &self.part_number
    }
    /// <p>Date and time at which the part was uploaded.</p>
    pub fn last_modified(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified = ::std::option::Option::Some(input);
        self
    }
    /// <p>Date and time at which the part was uploaded.</p>
    pub fn set_last_modified(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified = input;
        self
    }
    /// <p>Date and time at which the part was uploaded.</p>
    pub fn get_last_modified(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified
    }
    /// <p>Entity tag returned when the part was uploaded.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Entity tag returned when the part was uploaded.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>Entity tag returned when the part was uploaded.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    /// <p>Size in bytes of the uploaded part data.</p>
    pub fn size(mut self, input: i64) -> Self {
        self.size = ::std::option::Option::Some(input);
        self
    }
    /// <p>Size in bytes of the uploaded part data.</p>
    pub fn set_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size = input;
        self
    }
    /// <p>Size in bytes of the uploaded part data.</p>
    pub fn get_size(&self) -> &::std::option::Option<i64> {
        &self.size
    }
    /// <p>The Base64 encoded, 32-bit <code>CRC32</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_crc32(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.checksum_crc32 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Base64 encoded, 32-bit <code>CRC32</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn set_checksum_crc32(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.checksum_crc32 = input;
        self
    }
    /// <p>The Base64 encoded, 32-bit <code>CRC32</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn get_checksum_crc32(&self) -> &::std::option::Option<::std::string::String> {
        &self.checksum_crc32
    }
    /// <p>The Base64 encoded, 32-bit <code>CRC32C</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32C</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_crc32_c(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.checksum_crc32_c = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Base64 encoded, 32-bit <code>CRC32C</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32C</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn set_checksum_crc32_c(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.checksum_crc32_c = input;
        self
    }
    /// <p>The Base64 encoded, 32-bit <code>CRC32C</code> checksum of the part. This checksum is present if the object was uploaded with the <code>CRC32C</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn get_checksum_crc32_c(&self) -> &::std::option::Option<::std::string::String> {
        &self.checksum_crc32_c
    }
    /// <p>The Base64 encoded, 64-bit <code>CRC64NVME</code> checksum of the part. This checksum is present if the multipart upload request was created with the <code>CRC64NVME</code> checksum algorithm, or if the object was uploaded without a checksum (and Amazon S3 added the default checksum, <code>CRC64NVME</code>, to the uploaded object). For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_crc64_nvme(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.checksum_crc64_nvme = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Base64 encoded, 64-bit <code>CRC64NVME</code> checksum of the part. This checksum is present if the multipart upload request was created with the <code>CRC64NVME</code> checksum algorithm, or if the object was uploaded without a checksum (and Amazon S3 added the default checksum, <code>CRC64NVME</code>, to the uploaded object). For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn set_checksum_crc64_nvme(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.checksum_crc64_nvme = input;
        self
    }
    /// <p>The Base64 encoded, 64-bit <code>CRC64NVME</code> checksum of the part. This checksum is present if the multipart upload request was created with the <code>CRC64NVME</code> checksum algorithm, or if the object was uploaded without a checksum (and Amazon S3 added the default checksum, <code>CRC64NVME</code>, to the uploaded object). For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn get_checksum_crc64_nvme(&self) -> &::std::option::Option<::std::string::String> {
        &self.checksum_crc64_nvme
    }
    /// <p>The Base64 encoded, 160-bit <code>SHA1</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA1</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_sha1(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.checksum_sha1 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Base64 encoded, 160-bit <code>SHA1</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA1</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn set_checksum_sha1(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.checksum_sha1 = input;
        self
    }
    /// <p>The Base64 encoded, 160-bit <code>SHA1</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA1</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn get_checksum_sha1(&self) -> &::std::option::Option<::std::string::String> {
        &self.checksum_sha1
    }
    /// <p>The Base64 encoded, 256-bit <code>SHA256</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA256</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn checksum_sha256(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.checksum_sha256 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Base64 encoded, 256-bit <code>SHA256</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA256</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn set_checksum_sha256(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.checksum_sha256 = input;
        self
    }
    /// <p>The Base64 encoded, 256-bit <code>SHA256</code> checksum of the part. This checksum is present if the object was uploaded with the <code>SHA256</code> checksum algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    pub fn get_checksum_sha256(&self) -> &::std::option::Option<::std::string::String> {
        &self.checksum_sha256
    }
    /// Consumes the builder and constructs a [`Part`](crate::types::Part).
    pub fn build(self) -> crate::types::Part {
        crate::types::Part {
            part_number: self.part_number,
            last_modified: self.last_modified,
            e_tag: self.e_tag,
            size: self.size,
            checksum_crc32: self.checksum_crc32,
            checksum_crc32_c: self.checksum_crc32_c,
            checksum_crc64_nvme: self.checksum_crc64_nvme,
            checksum_sha1: self.checksum_sha1,
            checksum_sha256: self.checksum_sha256,
        }
    }
}
