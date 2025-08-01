// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRegionalBucketsInput {
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p></p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p></p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The ID of the Outposts resource.</p><note>
    /// <p>This ID is required by Amazon S3 on Outposts buckets.</p>
    /// </note>
    pub outpost_id: ::std::option::Option<::std::string::String>,
}
impl ListRegionalBucketsInput {
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p></p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p></p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The ID of the Outposts resource.</p><note>
    /// <p>This ID is required by Amazon S3 on Outposts buckets.</p>
    /// </note>
    pub fn outpost_id(&self) -> ::std::option::Option<&str> {
        self.outpost_id.as_deref()
    }
}
impl ListRegionalBucketsInput {
    /// Creates a new builder-style object to manufacture [`ListRegionalBucketsInput`](crate::operation::list_regional_buckets::ListRegionalBucketsInput).
    pub fn builder() -> crate::operation::list_regional_buckets::builders::ListRegionalBucketsInputBuilder {
        crate::operation::list_regional_buckets::builders::ListRegionalBucketsInputBuilder::default()
    }
}

/// A builder for [`ListRegionalBucketsInput`](crate::operation::list_regional_buckets::ListRegionalBucketsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRegionalBucketsInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) outpost_id: ::std::option::Option<::std::string::String>,
}
impl ListRegionalBucketsInputBuilder {
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p></p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p></p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p></p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p></p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The ID of the Outposts resource.</p><note>
    /// <p>This ID is required by Amazon S3 on Outposts buckets.</p>
    /// </note>
    pub fn outpost_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.outpost_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Outposts resource.</p><note>
    /// <p>This ID is required by Amazon S3 on Outposts buckets.</p>
    /// </note>
    pub fn set_outpost_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.outpost_id = input;
        self
    }
    /// <p>The ID of the Outposts resource.</p><note>
    /// <p>This ID is required by Amazon S3 on Outposts buckets.</p>
    /// </note>
    pub fn get_outpost_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.outpost_id
    }
    /// Consumes the builder and constructs a [`ListRegionalBucketsInput`](crate::operation::list_regional_buckets::ListRegionalBucketsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_regional_buckets::ListRegionalBucketsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_regional_buckets::ListRegionalBucketsInput {
            account_id: self.account_id,
            next_token: self.next_token,
            max_results: self.max_results,
            outpost_id: self.outpost_id,
        })
    }
}
