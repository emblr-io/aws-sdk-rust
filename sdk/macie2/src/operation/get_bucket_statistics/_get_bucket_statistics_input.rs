// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBucketStatisticsInput {
    /// <p>The unique identifier for the Amazon Web Services account.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl GetBucketStatisticsInput {
    /// <p>The unique identifier for the Amazon Web Services account.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl GetBucketStatisticsInput {
    /// Creates a new builder-style object to manufacture [`GetBucketStatisticsInput`](crate::operation::get_bucket_statistics::GetBucketStatisticsInput).
    pub fn builder() -> crate::operation::get_bucket_statistics::builders::GetBucketStatisticsInputBuilder {
        crate::operation::get_bucket_statistics::builders::GetBucketStatisticsInputBuilder::default()
    }
}

/// A builder for [`GetBucketStatisticsInput`](crate::operation::get_bucket_statistics::GetBucketStatisticsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetBucketStatisticsInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl GetBucketStatisticsInputBuilder {
    /// <p>The unique identifier for the Amazon Web Services account.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the Amazon Web Services account.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The unique identifier for the Amazon Web Services account.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`GetBucketStatisticsInput`](crate::operation::get_bucket_statistics::GetBucketStatisticsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_bucket_statistics::GetBucketStatisticsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_bucket_statistics::GetBucketStatisticsInput { account_id: self.account_id })
    }
}
