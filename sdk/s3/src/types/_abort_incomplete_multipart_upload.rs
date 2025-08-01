// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the days since the initiation of an incomplete multipart upload that Amazon S3 will wait before permanently removing all parts of the upload. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuoverview.html#mpu-abort-incomplete-mpu-lifecycle-config"> Aborting Incomplete Multipart Uploads Using a Bucket Lifecycle Configuration</a> in the <i>Amazon S3 User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AbortIncompleteMultipartUpload {
    /// <p>Specifies the number of days after which Amazon S3 aborts an incomplete multipart upload.</p>
    pub days_after_initiation: ::std::option::Option<i32>,
}
impl AbortIncompleteMultipartUpload {
    /// <p>Specifies the number of days after which Amazon S3 aborts an incomplete multipart upload.</p>
    pub fn days_after_initiation(&self) -> ::std::option::Option<i32> {
        self.days_after_initiation
    }
}
impl AbortIncompleteMultipartUpload {
    /// Creates a new builder-style object to manufacture [`AbortIncompleteMultipartUpload`](crate::types::AbortIncompleteMultipartUpload).
    pub fn builder() -> crate::types::builders::AbortIncompleteMultipartUploadBuilder {
        crate::types::builders::AbortIncompleteMultipartUploadBuilder::default()
    }
}

/// A builder for [`AbortIncompleteMultipartUpload`](crate::types::AbortIncompleteMultipartUpload).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AbortIncompleteMultipartUploadBuilder {
    pub(crate) days_after_initiation: ::std::option::Option<i32>,
}
impl AbortIncompleteMultipartUploadBuilder {
    /// <p>Specifies the number of days after which Amazon S3 aborts an incomplete multipart upload.</p>
    pub fn days_after_initiation(mut self, input: i32) -> Self {
        self.days_after_initiation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the number of days after which Amazon S3 aborts an incomplete multipart upload.</p>
    pub fn set_days_after_initiation(mut self, input: ::std::option::Option<i32>) -> Self {
        self.days_after_initiation = input;
        self
    }
    /// <p>Specifies the number of days after which Amazon S3 aborts an incomplete multipart upload.</p>
    pub fn get_days_after_initiation(&self) -> &::std::option::Option<i32> {
        &self.days_after_initiation
    }
    /// Consumes the builder and constructs a [`AbortIncompleteMultipartUpload`](crate::types::AbortIncompleteMultipartUpload).
    pub fn build(self) -> crate::types::AbortIncompleteMultipartUpload {
        crate::types::AbortIncompleteMultipartUpload {
            days_after_initiation: self.days_after_initiation,
        }
    }
}
