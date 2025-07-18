// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutBucketEncryptionInput {
    /// <p>Specifies default encryption for a bucket using server-side encryption with different key options.</p>
    /// <p><b>Directory buckets </b> - When you use this operation with a directory bucket, you must use path-style requests in the format <code>https://s3express-control.<i>region-code</i>.amazonaws.com/<i>bucket-name</i> </code>. Virtual-hosted-style requests aren't supported. Directory bucket names must be unique in the chosen Zone (Availability Zone or Local Zone). Bucket names must also follow the format <code> <i>bucket-base-name</i>--<i>zone-id</i>--x-s3</code> (for example, <code> <i>DOC-EXAMPLE-BUCKET</i>--<i>usw2-az1</i>--x-s3</code>). For information about bucket naming restrictions, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html">Directory bucket naming rules</a> in the <i>Amazon S3 User Guide</i></p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the server-side encryption configuration.</p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub content_md5: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p><note>
    /// <p>For directory buckets, when you use Amazon Web Services SDKs, <code>CRC32</code> is the default checksum algorithm that's used for performance.</p>
    /// </note>
    pub checksum_algorithm: ::std::option::Option<crate::types::ChecksumAlgorithm>,
    /// <p>Specifies the default server-side-encryption configuration.</p>
    pub server_side_encryption_configuration: ::std::option::Option<crate::types::ServerSideEncryptionConfiguration>,
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><note>
    /// <p>For directory buckets, this header is not supported in this API operation. If you specify this header, the request fails with the HTTP status code <code>501 Not Implemented</code>.</p>
    /// </note>
    pub expected_bucket_owner: ::std::option::Option<::std::string::String>,
}
impl PutBucketEncryptionInput {
    /// <p>Specifies default encryption for a bucket using server-side encryption with different key options.</p>
    /// <p><b>Directory buckets </b> - When you use this operation with a directory bucket, you must use path-style requests in the format <code>https://s3express-control.<i>region-code</i>.amazonaws.com/<i>bucket-name</i> </code>. Virtual-hosted-style requests aren't supported. Directory bucket names must be unique in the chosen Zone (Availability Zone or Local Zone). Bucket names must also follow the format <code> <i>bucket-base-name</i>--<i>zone-id</i>--x-s3</code> (for example, <code> <i>DOC-EXAMPLE-BUCKET</i>--<i>usw2-az1</i>--x-s3</code>). For information about bucket naming restrictions, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html">Directory bucket naming rules</a> in the <i>Amazon S3 User Guide</i></p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the server-side encryption configuration.</p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn content_md5(&self) -> ::std::option::Option<&str> {
        self.content_md5.as_deref()
    }
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p><note>
    /// <p>For directory buckets, when you use Amazon Web Services SDKs, <code>CRC32</code> is the default checksum algorithm that's used for performance.</p>
    /// </note>
    pub fn checksum_algorithm(&self) -> ::std::option::Option<&crate::types::ChecksumAlgorithm> {
        self.checksum_algorithm.as_ref()
    }
    /// <p>Specifies the default server-side-encryption configuration.</p>
    pub fn server_side_encryption_configuration(&self) -> ::std::option::Option<&crate::types::ServerSideEncryptionConfiguration> {
        self.server_side_encryption_configuration.as_ref()
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><note>
    /// <p>For directory buckets, this header is not supported in this API operation. If you specify this header, the request fails with the HTTP status code <code>501 Not Implemented</code>.</p>
    /// </note>
    pub fn expected_bucket_owner(&self) -> ::std::option::Option<&str> {
        self.expected_bucket_owner.as_deref()
    }
}
impl PutBucketEncryptionInput {
    /// Creates a new builder-style object to manufacture [`PutBucketEncryptionInput`](crate::operation::put_bucket_encryption::PutBucketEncryptionInput).
    pub fn builder() -> crate::operation::put_bucket_encryption::builders::PutBucketEncryptionInputBuilder {
        crate::operation::put_bucket_encryption::builders::PutBucketEncryptionInputBuilder::default()
    }
}

/// A builder for [`PutBucketEncryptionInput`](crate::operation::put_bucket_encryption::PutBucketEncryptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutBucketEncryptionInputBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) content_md5: ::std::option::Option<::std::string::String>,
    pub(crate) checksum_algorithm: ::std::option::Option<crate::types::ChecksumAlgorithm>,
    pub(crate) server_side_encryption_configuration: ::std::option::Option<crate::types::ServerSideEncryptionConfiguration>,
    pub(crate) expected_bucket_owner: ::std::option::Option<::std::string::String>,
}
impl PutBucketEncryptionInputBuilder {
    /// <p>Specifies default encryption for a bucket using server-side encryption with different key options.</p>
    /// <p><b>Directory buckets </b> - When you use this operation with a directory bucket, you must use path-style requests in the format <code>https://s3express-control.<i>region-code</i>.amazonaws.com/<i>bucket-name</i> </code>. Virtual-hosted-style requests aren't supported. Directory bucket names must be unique in the chosen Zone (Availability Zone or Local Zone). Bucket names must also follow the format <code> <i>bucket-base-name</i>--<i>zone-id</i>--x-s3</code> (for example, <code> <i>DOC-EXAMPLE-BUCKET</i>--<i>usw2-az1</i>--x-s3</code>). For information about bucket naming restrictions, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html">Directory bucket naming rules</a> in the <i>Amazon S3 User Guide</i></p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies default encryption for a bucket using server-side encryption with different key options.</p>
    /// <p><b>Directory buckets </b> - When you use this operation with a directory bucket, you must use path-style requests in the format <code>https://s3express-control.<i>region-code</i>.amazonaws.com/<i>bucket-name</i> </code>. Virtual-hosted-style requests aren't supported. Directory bucket names must be unique in the chosen Zone (Availability Zone or Local Zone). Bucket names must also follow the format <code> <i>bucket-base-name</i>--<i>zone-id</i>--x-s3</code> (for example, <code> <i>DOC-EXAMPLE-BUCKET</i>--<i>usw2-az1</i>--x-s3</code>). For information about bucket naming restrictions, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html">Directory bucket naming rules</a> in the <i>Amazon S3 User Guide</i></p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>Specifies default encryption for a bucket using server-side encryption with different key options.</p>
    /// <p><b>Directory buckets </b> - When you use this operation with a directory bucket, you must use path-style requests in the format <code>https://s3express-control.<i>region-code</i>.amazonaws.com/<i>bucket-name</i> </code>. Virtual-hosted-style requests aren't supported. Directory bucket names must be unique in the chosen Zone (Availability Zone or Local Zone). Bucket names must also follow the format <code> <i>bucket-base-name</i>--<i>zone-id</i>--x-s3</code> (for example, <code> <i>DOC-EXAMPLE-BUCKET</i>--<i>usw2-az1</i>--x-s3</code>). For information about bucket naming restrictions, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html">Directory bucket naming rules</a> in the <i>Amazon S3 User Guide</i></p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the server-side encryption configuration.</p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn content_md5(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_md5 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the server-side encryption configuration.</p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn set_content_md5(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_md5 = input;
        self
    }
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the server-side encryption configuration.</p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn get_content_md5(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_md5
    }
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p><note>
    /// <p>For directory buckets, when you use Amazon Web Services SDKs, <code>CRC32</code> is the default checksum algorithm that's used for performance.</p>
    /// </note>
    pub fn checksum_algorithm(mut self, input: crate::types::ChecksumAlgorithm) -> Self {
        self.checksum_algorithm = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p><note>
    /// <p>For directory buckets, when you use Amazon Web Services SDKs, <code>CRC32</code> is the default checksum algorithm that's used for performance.</p>
    /// </note>
    pub fn set_checksum_algorithm(mut self, input: ::std::option::Option<crate::types::ChecksumAlgorithm>) -> Self {
        self.checksum_algorithm = input;
        self
    }
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p><note>
    /// <p>For directory buckets, when you use Amazon Web Services SDKs, <code>CRC32</code> is the default checksum algorithm that's used for performance.</p>
    /// </note>
    pub fn get_checksum_algorithm(&self) -> &::std::option::Option<crate::types::ChecksumAlgorithm> {
        &self.checksum_algorithm
    }
    /// <p>Specifies the default server-side-encryption configuration.</p>
    /// This field is required.
    pub fn server_side_encryption_configuration(mut self, input: crate::types::ServerSideEncryptionConfiguration) -> Self {
        self.server_side_encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the default server-side-encryption configuration.</p>
    pub fn set_server_side_encryption_configuration(mut self, input: ::std::option::Option<crate::types::ServerSideEncryptionConfiguration>) -> Self {
        self.server_side_encryption_configuration = input;
        self
    }
    /// <p>Specifies the default server-side-encryption configuration.</p>
    pub fn get_server_side_encryption_configuration(&self) -> &::std::option::Option<crate::types::ServerSideEncryptionConfiguration> {
        &self.server_side_encryption_configuration
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><note>
    /// <p>For directory buckets, this header is not supported in this API operation. If you specify this header, the request fails with the HTTP status code <code>501 Not Implemented</code>.</p>
    /// </note>
    pub fn expected_bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expected_bucket_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><note>
    /// <p>For directory buckets, this header is not supported in this API operation. If you specify this header, the request fails with the HTTP status code <code>501 Not Implemented</code>.</p>
    /// </note>
    pub fn set_expected_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expected_bucket_owner = input;
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p><note>
    /// <p>For directory buckets, this header is not supported in this API operation. If you specify this header, the request fails with the HTTP status code <code>501 Not Implemented</code>.</p>
    /// </note>
    pub fn get_expected_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.expected_bucket_owner
    }
    /// Consumes the builder and constructs a [`PutBucketEncryptionInput`](crate::operation::put_bucket_encryption::PutBucketEncryptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_bucket_encryption::PutBucketEncryptionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::put_bucket_encryption::PutBucketEncryptionInput {
            bucket: self.bucket,
            content_md5: self.content_md5,
            checksum_algorithm: self.checksum_algorithm,
            server_side_encryption_configuration: self.server_side_encryption_configuration,
            expected_bucket_owner: self.expected_bucket_owner,
        })
    }
}
