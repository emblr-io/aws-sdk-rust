// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBucketLoggingOutput {
    /// <p>Describes where logs are stored and the prefix that Amazon S3 assigns to all log object keys for a bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlogging.html">PUT Bucket logging</a> in the <i>Amazon S3 API Reference</i>.</p>
    pub logging_enabled: ::std::option::Option<crate::types::LoggingEnabled>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl GetBucketLoggingOutput {
    /// <p>Describes where logs are stored and the prefix that Amazon S3 assigns to all log object keys for a bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlogging.html">PUT Bucket logging</a> in the <i>Amazon S3 API Reference</i>.</p>
    pub fn logging_enabled(&self) -> ::std::option::Option<&crate::types::LoggingEnabled> {
        self.logging_enabled.as_ref()
    }
}
impl crate::s3_request_id::RequestIdExt for GetBucketLoggingOutput {
    fn extended_request_id(&self) -> Option<&str> {
        self._extended_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetBucketLoggingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetBucketLoggingOutput {
    /// Creates a new builder-style object to manufacture [`GetBucketLoggingOutput`](crate::operation::get_bucket_logging::GetBucketLoggingOutput).
    pub fn builder() -> crate::operation::get_bucket_logging::builders::GetBucketLoggingOutputBuilder {
        crate::operation::get_bucket_logging::builders::GetBucketLoggingOutputBuilder::default()
    }
}

/// A builder for [`GetBucketLoggingOutput`](crate::operation::get_bucket_logging::GetBucketLoggingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetBucketLoggingOutputBuilder {
    pub(crate) logging_enabled: ::std::option::Option<crate::types::LoggingEnabled>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl GetBucketLoggingOutputBuilder {
    /// <p>Describes where logs are stored and the prefix that Amazon S3 assigns to all log object keys for a bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlogging.html">PUT Bucket logging</a> in the <i>Amazon S3 API Reference</i>.</p>
    pub fn logging_enabled(mut self, input: crate::types::LoggingEnabled) -> Self {
        self.logging_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes where logs are stored and the prefix that Amazon S3 assigns to all log object keys for a bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlogging.html">PUT Bucket logging</a> in the <i>Amazon S3 API Reference</i>.</p>
    pub fn set_logging_enabled(mut self, input: ::std::option::Option<crate::types::LoggingEnabled>) -> Self {
        self.logging_enabled = input;
        self
    }
    /// <p>Describes where logs are stored and the prefix that Amazon S3 assigns to all log object keys for a bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlogging.html">PUT Bucket logging</a> in the <i>Amazon S3 API Reference</i>.</p>
    pub fn get_logging_enabled(&self) -> &::std::option::Option<crate::types::LoggingEnabled> {
        &self.logging_enabled
    }
    pub(crate) fn _extended_request_id(mut self, extended_request_id: impl Into<String>) -> Self {
        self._extended_request_id = Some(extended_request_id.into());
        self
    }

    pub(crate) fn _set_extended_request_id(&mut self, extended_request_id: Option<String>) -> &mut Self {
        self._extended_request_id = extended_request_id;
        self
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetBucketLoggingOutput`](crate::operation::get_bucket_logging::GetBucketLoggingOutput).
    pub fn build(self) -> crate::operation::get_bucket_logging::GetBucketLoggingOutput {
        crate::operation::get_bucket_logging::GetBucketLoggingOutput {
            logging_enabled: self.logging_enabled,
            _extended_request_id: self._extended_request_id,
            _request_id: self._request_id,
        }
    }
}
