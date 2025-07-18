// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTableBucketsInput {
    /// <p>The prefix of the table buckets.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p><code>ContinuationToken</code> indicates to Amazon S3 that the list is being continued on this bucket with a token. <code>ContinuationToken</code> is obfuscated and is not a real key. You can use this <code>ContinuationToken</code> for pagination of the list results.</p>
    pub continuation_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of table buckets to return in the list.</p>
    pub max_buckets: ::std::option::Option<i32>,
}
impl ListTableBucketsInput {
    /// <p>The prefix of the table buckets.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p><code>ContinuationToken</code> indicates to Amazon S3 that the list is being continued on this bucket with a token. <code>ContinuationToken</code> is obfuscated and is not a real key. You can use this <code>ContinuationToken</code> for pagination of the list results.</p>
    pub fn continuation_token(&self) -> ::std::option::Option<&str> {
        self.continuation_token.as_deref()
    }
    /// <p>The maximum number of table buckets to return in the list.</p>
    pub fn max_buckets(&self) -> ::std::option::Option<i32> {
        self.max_buckets
    }
}
impl ListTableBucketsInput {
    /// Creates a new builder-style object to manufacture [`ListTableBucketsInput`](crate::operation::list_table_buckets::ListTableBucketsInput).
    pub fn builder() -> crate::operation::list_table_buckets::builders::ListTableBucketsInputBuilder {
        crate::operation::list_table_buckets::builders::ListTableBucketsInputBuilder::default()
    }
}

/// A builder for [`ListTableBucketsInput`](crate::operation::list_table_buckets::ListTableBucketsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTableBucketsInputBuilder {
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) continuation_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_buckets: ::std::option::Option<i32>,
}
impl ListTableBucketsInputBuilder {
    /// <p>The prefix of the table buckets.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prefix of the table buckets.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>The prefix of the table buckets.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// <p><code>ContinuationToken</code> indicates to Amazon S3 that the list is being continued on this bucket with a token. <code>ContinuationToken</code> is obfuscated and is not a real key. You can use this <code>ContinuationToken</code> for pagination of the list results.</p>
    pub fn continuation_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.continuation_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><code>ContinuationToken</code> indicates to Amazon S3 that the list is being continued on this bucket with a token. <code>ContinuationToken</code> is obfuscated and is not a real key. You can use this <code>ContinuationToken</code> for pagination of the list results.</p>
    pub fn set_continuation_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.continuation_token = input;
        self
    }
    /// <p><code>ContinuationToken</code> indicates to Amazon S3 that the list is being continued on this bucket with a token. <code>ContinuationToken</code> is obfuscated and is not a real key. You can use this <code>ContinuationToken</code> for pagination of the list results.</p>
    pub fn get_continuation_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.continuation_token
    }
    /// <p>The maximum number of table buckets to return in the list.</p>
    pub fn max_buckets(mut self, input: i32) -> Self {
        self.max_buckets = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of table buckets to return in the list.</p>
    pub fn set_max_buckets(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_buckets = input;
        self
    }
    /// <p>The maximum number of table buckets to return in the list.</p>
    pub fn get_max_buckets(&self) -> &::std::option::Option<i32> {
        &self.max_buckets
    }
    /// Consumes the builder and constructs a [`ListTableBucketsInput`](crate::operation::list_table_buckets::ListTableBucketsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_table_buckets::ListTableBucketsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_table_buckets::ListTableBucketsInput {
            prefix: self.prefix,
            continuation_token: self.continuation_token,
            max_buckets: self.max_buckets,
        })
    }
}
