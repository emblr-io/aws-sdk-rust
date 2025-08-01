// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutBucketVersioningOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PutBucketVersioningOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutBucketVersioningOutput {
    /// Creates a new builder-style object to manufacture [`PutBucketVersioningOutput`](crate::operation::put_bucket_versioning::PutBucketVersioningOutput).
    pub fn builder() -> crate::operation::put_bucket_versioning::builders::PutBucketVersioningOutputBuilder {
        crate::operation::put_bucket_versioning::builders::PutBucketVersioningOutputBuilder::default()
    }
}

/// A builder for [`PutBucketVersioningOutput`](crate::operation::put_bucket_versioning::PutBucketVersioningOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutBucketVersioningOutputBuilder {
    _request_id: Option<String>,
}
impl PutBucketVersioningOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutBucketVersioningOutput`](crate::operation::put_bucket_versioning::PutBucketVersioningOutput).
    pub fn build(self) -> crate::operation::put_bucket_versioning::PutBucketVersioningOutput {
        crate::operation::put_bucket_versioning::PutBucketVersioningOutput {
            _request_id: self._request_id,
        }
    }
}
