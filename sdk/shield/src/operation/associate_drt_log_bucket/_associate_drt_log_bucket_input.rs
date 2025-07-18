// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateDrtLogBucketInput {
    /// <p>The Amazon S3 bucket that contains the logs that you want to share.</p>
    pub log_bucket: ::std::option::Option<::std::string::String>,
}
impl AssociateDrtLogBucketInput {
    /// <p>The Amazon S3 bucket that contains the logs that you want to share.</p>
    pub fn log_bucket(&self) -> ::std::option::Option<&str> {
        self.log_bucket.as_deref()
    }
}
impl AssociateDrtLogBucketInput {
    /// Creates a new builder-style object to manufacture [`AssociateDrtLogBucketInput`](crate::operation::associate_drt_log_bucket::AssociateDrtLogBucketInput).
    pub fn builder() -> crate::operation::associate_drt_log_bucket::builders::AssociateDrtLogBucketInputBuilder {
        crate::operation::associate_drt_log_bucket::builders::AssociateDrtLogBucketInputBuilder::default()
    }
}

/// A builder for [`AssociateDrtLogBucketInput`](crate::operation::associate_drt_log_bucket::AssociateDrtLogBucketInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateDrtLogBucketInputBuilder {
    pub(crate) log_bucket: ::std::option::Option<::std::string::String>,
}
impl AssociateDrtLogBucketInputBuilder {
    /// <p>The Amazon S3 bucket that contains the logs that you want to share.</p>
    /// This field is required.
    pub fn log_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 bucket that contains the logs that you want to share.</p>
    pub fn set_log_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_bucket = input;
        self
    }
    /// <p>The Amazon S3 bucket that contains the logs that you want to share.</p>
    pub fn get_log_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_bucket
    }
    /// Consumes the builder and constructs a [`AssociateDrtLogBucketInput`](crate::operation::associate_drt_log_bucket::AssociateDrtLogBucketInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::associate_drt_log_bucket::AssociateDrtLogBucketInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::associate_drt_log_bucket::AssociateDrtLogBucketInput { log_bucket: self.log_bucket })
    }
}
