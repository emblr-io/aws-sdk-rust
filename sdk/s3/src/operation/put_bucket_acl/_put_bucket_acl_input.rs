// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutBucketAclInput {
    /// <p>The canned ACL to apply to the bucket.</p>
    pub acl: ::std::option::Option<crate::types::BucketCannedAcl>,
    /// <p>Contains the elements that set the ACL permissions for an object per grantee.</p>
    pub access_control_policy: ::std::option::Option<crate::types::AccessControlPolicy>,
    /// <p>The bucket to which to apply the ACL.</p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the data. This header must be used as a message integrity check to verify that the request body was not corrupted in transit. For more information, go to <a href="http://www.ietf.org/rfc/rfc1864.txt">RFC 1864.</a></p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p>
    pub content_md5: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p>
    pub checksum_algorithm: ::std::option::Option<crate::types::ChecksumAlgorithm>,
    /// <p>Allows grantee the read, write, read ACP, and write ACP permissions on the bucket.</p>
    pub grant_full_control: ::std::option::Option<::std::string::String>,
    /// <p>Allows grantee to list the objects in the bucket.</p>
    pub grant_read: ::std::option::Option<::std::string::String>,
    /// <p>Allows grantee to read the bucket ACL.</p>
    pub grant_read_acp: ::std::option::Option<::std::string::String>,
    /// <p>Allows grantee to create new objects in the bucket.</p>
    /// <p>For the bucket and object owners of existing objects, also allows deletions and overwrites of those objects.</p>
    pub grant_write: ::std::option::Option<::std::string::String>,
    /// <p>Allows grantee to write the ACL for the applicable bucket.</p>
    pub grant_write_acp: ::std::option::Option<::std::string::String>,
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub expected_bucket_owner: ::std::option::Option<::std::string::String>,
}
impl PutBucketAclInput {
    /// <p>The canned ACL to apply to the bucket.</p>
    pub fn acl(&self) -> ::std::option::Option<&crate::types::BucketCannedAcl> {
        self.acl.as_ref()
    }
    /// <p>Contains the elements that set the ACL permissions for an object per grantee.</p>
    pub fn access_control_policy(&self) -> ::std::option::Option<&crate::types::AccessControlPolicy> {
        self.access_control_policy.as_ref()
    }
    /// <p>The bucket to which to apply the ACL.</p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the data. This header must be used as a message integrity check to verify that the request body was not corrupted in transit. For more information, go to <a href="http://www.ietf.org/rfc/rfc1864.txt">RFC 1864.</a></p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p>
    pub fn content_md5(&self) -> ::std::option::Option<&str> {
        self.content_md5.as_deref()
    }
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p>
    pub fn checksum_algorithm(&self) -> ::std::option::Option<&crate::types::ChecksumAlgorithm> {
        self.checksum_algorithm.as_ref()
    }
    /// <p>Allows grantee the read, write, read ACP, and write ACP permissions on the bucket.</p>
    pub fn grant_full_control(&self) -> ::std::option::Option<&str> {
        self.grant_full_control.as_deref()
    }
    /// <p>Allows grantee to list the objects in the bucket.</p>
    pub fn grant_read(&self) -> ::std::option::Option<&str> {
        self.grant_read.as_deref()
    }
    /// <p>Allows grantee to read the bucket ACL.</p>
    pub fn grant_read_acp(&self) -> ::std::option::Option<&str> {
        self.grant_read_acp.as_deref()
    }
    /// <p>Allows grantee to create new objects in the bucket.</p>
    /// <p>For the bucket and object owners of existing objects, also allows deletions and overwrites of those objects.</p>
    pub fn grant_write(&self) -> ::std::option::Option<&str> {
        self.grant_write.as_deref()
    }
    /// <p>Allows grantee to write the ACL for the applicable bucket.</p>
    pub fn grant_write_acp(&self) -> ::std::option::Option<&str> {
        self.grant_write_acp.as_deref()
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(&self) -> ::std::option::Option<&str> {
        self.expected_bucket_owner.as_deref()
    }
}
impl PutBucketAclInput {
    /// Creates a new builder-style object to manufacture [`PutBucketAclInput`](crate::operation::put_bucket_acl::PutBucketAclInput).
    pub fn builder() -> crate::operation::put_bucket_acl::builders::PutBucketAclInputBuilder {
        crate::operation::put_bucket_acl::builders::PutBucketAclInputBuilder::default()
    }
}

/// A builder for [`PutBucketAclInput`](crate::operation::put_bucket_acl::PutBucketAclInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutBucketAclInputBuilder {
    pub(crate) acl: ::std::option::Option<crate::types::BucketCannedAcl>,
    pub(crate) access_control_policy: ::std::option::Option<crate::types::AccessControlPolicy>,
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) content_md5: ::std::option::Option<::std::string::String>,
    pub(crate) checksum_algorithm: ::std::option::Option<crate::types::ChecksumAlgorithm>,
    pub(crate) grant_full_control: ::std::option::Option<::std::string::String>,
    pub(crate) grant_read: ::std::option::Option<::std::string::String>,
    pub(crate) grant_read_acp: ::std::option::Option<::std::string::String>,
    pub(crate) grant_write: ::std::option::Option<::std::string::String>,
    pub(crate) grant_write_acp: ::std::option::Option<::std::string::String>,
    pub(crate) expected_bucket_owner: ::std::option::Option<::std::string::String>,
}
impl PutBucketAclInputBuilder {
    /// <p>The canned ACL to apply to the bucket.</p>
    pub fn acl(mut self, input: crate::types::BucketCannedAcl) -> Self {
        self.acl = ::std::option::Option::Some(input);
        self
    }
    /// <p>The canned ACL to apply to the bucket.</p>
    pub fn set_acl(mut self, input: ::std::option::Option<crate::types::BucketCannedAcl>) -> Self {
        self.acl = input;
        self
    }
    /// <p>The canned ACL to apply to the bucket.</p>
    pub fn get_acl(&self) -> &::std::option::Option<crate::types::BucketCannedAcl> {
        &self.acl
    }
    /// <p>Contains the elements that set the ACL permissions for an object per grantee.</p>
    pub fn access_control_policy(mut self, input: crate::types::AccessControlPolicy) -> Self {
        self.access_control_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the elements that set the ACL permissions for an object per grantee.</p>
    pub fn set_access_control_policy(mut self, input: ::std::option::Option<crate::types::AccessControlPolicy>) -> Self {
        self.access_control_policy = input;
        self
    }
    /// <p>Contains the elements that set the ACL permissions for an object per grantee.</p>
    pub fn get_access_control_policy(&self) -> &::std::option::Option<crate::types::AccessControlPolicy> {
        &self.access_control_policy
    }
    /// <p>The bucket to which to apply the ACL.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The bucket to which to apply the ACL.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The bucket to which to apply the ACL.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the data. This header must be used as a message integrity check to verify that the request body was not corrupted in transit. For more information, go to <a href="http://www.ietf.org/rfc/rfc1864.txt">RFC 1864.</a></p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p>
    pub fn content_md5(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_md5 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the data. This header must be used as a message integrity check to verify that the request body was not corrupted in transit. For more information, go to <a href="http://www.ietf.org/rfc/rfc1864.txt">RFC 1864.</a></p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p>
    pub fn set_content_md5(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_md5 = input;
        self
    }
    /// <p>The Base64 encoded 128-bit <code>MD5</code> digest of the data. This header must be used as a message integrity check to verify that the request body was not corrupted in transit. For more information, go to <a href="http://www.ietf.org/rfc/rfc1864.txt">RFC 1864.</a></p>
    /// <p>For requests made using the Amazon Web Services Command Line Interface (CLI) or Amazon Web Services SDKs, this field is calculated automatically.</p>
    pub fn get_content_md5(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_md5
    }
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p>
    pub fn checksum_algorithm(mut self, input: crate::types::ChecksumAlgorithm) -> Self {
        self.checksum_algorithm = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p>
    pub fn set_checksum_algorithm(mut self, input: ::std::option::Option<crate::types::ChecksumAlgorithm>) -> Self {
        self.checksum_algorithm = input;
        self
    }
    /// <p>Indicates the algorithm used to create the checksum for the request when you use the SDK. This header will not provide any additional functionality if you don't use the SDK. When you send this header, there must be a corresponding <code>x-amz-checksum</code> or <code>x-amz-trailer</code> header sent. Otherwise, Amazon S3 fails the request with the HTTP status code <code>400 Bad Request</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html">Checking object integrity</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>If you provide an individual checksum, Amazon S3 ignores any provided <code>ChecksumAlgorithm</code> parameter.</p>
    pub fn get_checksum_algorithm(&self) -> &::std::option::Option<crate::types::ChecksumAlgorithm> {
        &self.checksum_algorithm
    }
    /// <p>Allows grantee the read, write, read ACP, and write ACP permissions on the bucket.</p>
    pub fn grant_full_control(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.grant_full_control = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Allows grantee the read, write, read ACP, and write ACP permissions on the bucket.</p>
    pub fn set_grant_full_control(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.grant_full_control = input;
        self
    }
    /// <p>Allows grantee the read, write, read ACP, and write ACP permissions on the bucket.</p>
    pub fn get_grant_full_control(&self) -> &::std::option::Option<::std::string::String> {
        &self.grant_full_control
    }
    /// <p>Allows grantee to list the objects in the bucket.</p>
    pub fn grant_read(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.grant_read = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Allows grantee to list the objects in the bucket.</p>
    pub fn set_grant_read(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.grant_read = input;
        self
    }
    /// <p>Allows grantee to list the objects in the bucket.</p>
    pub fn get_grant_read(&self) -> &::std::option::Option<::std::string::String> {
        &self.grant_read
    }
    /// <p>Allows grantee to read the bucket ACL.</p>
    pub fn grant_read_acp(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.grant_read_acp = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Allows grantee to read the bucket ACL.</p>
    pub fn set_grant_read_acp(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.grant_read_acp = input;
        self
    }
    /// <p>Allows grantee to read the bucket ACL.</p>
    pub fn get_grant_read_acp(&self) -> &::std::option::Option<::std::string::String> {
        &self.grant_read_acp
    }
    /// <p>Allows grantee to create new objects in the bucket.</p>
    /// <p>For the bucket and object owners of existing objects, also allows deletions and overwrites of those objects.</p>
    pub fn grant_write(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.grant_write = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Allows grantee to create new objects in the bucket.</p>
    /// <p>For the bucket and object owners of existing objects, also allows deletions and overwrites of those objects.</p>
    pub fn set_grant_write(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.grant_write = input;
        self
    }
    /// <p>Allows grantee to create new objects in the bucket.</p>
    /// <p>For the bucket and object owners of existing objects, also allows deletions and overwrites of those objects.</p>
    pub fn get_grant_write(&self) -> &::std::option::Option<::std::string::String> {
        &self.grant_write
    }
    /// <p>Allows grantee to write the ACL for the applicable bucket.</p>
    pub fn grant_write_acp(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.grant_write_acp = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Allows grantee to write the ACL for the applicable bucket.</p>
    pub fn set_grant_write_acp(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.grant_write_acp = input;
        self
    }
    /// <p>Allows grantee to write the ACL for the applicable bucket.</p>
    pub fn get_grant_write_acp(&self) -> &::std::option::Option<::std::string::String> {
        &self.grant_write_acp
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expected_bucket_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn set_expected_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expected_bucket_owner = input;
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn get_expected_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.expected_bucket_owner
    }
    /// Consumes the builder and constructs a [`PutBucketAclInput`](crate::operation::put_bucket_acl::PutBucketAclInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_bucket_acl::PutBucketAclInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_bucket_acl::PutBucketAclInput {
            acl: self.acl,
            access_control_policy: self.access_control_policy,
            bucket: self.bucket,
            content_md5: self.content_md5,
            checksum_algorithm: self.checksum_algorithm,
            grant_full_control: self.grant_full_control,
            grant_read: self.grant_read,
            grant_read_acp: self.grant_read_acp,
            grant_write: self.grant_write,
            grant_write_acp: self.grant_write_acp,
            expected_bucket_owner: self.expected_bucket_owner,
        })
    }
}
