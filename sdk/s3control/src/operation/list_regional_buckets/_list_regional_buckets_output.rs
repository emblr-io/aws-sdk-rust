// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRegionalBucketsOutput {
    /// <p></p>
    pub regional_bucket_list: ::std::option::Option<::std::vec::Vec<crate::types::RegionalBucket>>,
    /// <p><code>NextToken</code> is sent when <code>isTruncated</code> is true, which means there are more buckets that can be listed. The next list requests to Amazon S3 can be continued with this <code>NextToken</code>. <code>NextToken</code> is obfuscated and is not a real key.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRegionalBucketsOutput {
    /// <p></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.regional_bucket_list.is_none()`.
    pub fn regional_bucket_list(&self) -> &[crate::types::RegionalBucket] {
        self.regional_bucket_list.as_deref().unwrap_or_default()
    }
    /// <p><code>NextToken</code> is sent when <code>isTruncated</code> is true, which means there are more buckets that can be listed. The next list requests to Amazon S3 can be continued with this <code>NextToken</code>. <code>NextToken</code> is obfuscated and is not a real key.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListRegionalBucketsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRegionalBucketsOutput {
    /// Creates a new builder-style object to manufacture [`ListRegionalBucketsOutput`](crate::operation::list_regional_buckets::ListRegionalBucketsOutput).
    pub fn builder() -> crate::operation::list_regional_buckets::builders::ListRegionalBucketsOutputBuilder {
        crate::operation::list_regional_buckets::builders::ListRegionalBucketsOutputBuilder::default()
    }
}

/// A builder for [`ListRegionalBucketsOutput`](crate::operation::list_regional_buckets::ListRegionalBucketsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRegionalBucketsOutputBuilder {
    pub(crate) regional_bucket_list: ::std::option::Option<::std::vec::Vec<crate::types::RegionalBucket>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRegionalBucketsOutputBuilder {
    /// Appends an item to `regional_bucket_list`.
    ///
    /// To override the contents of this collection use [`set_regional_bucket_list`](Self::set_regional_bucket_list).
    ///
    /// <p></p>
    pub fn regional_bucket_list(mut self, input: crate::types::RegionalBucket) -> Self {
        let mut v = self.regional_bucket_list.unwrap_or_default();
        v.push(input);
        self.regional_bucket_list = ::std::option::Option::Some(v);
        self
    }
    /// <p></p>
    pub fn set_regional_bucket_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RegionalBucket>>) -> Self {
        self.regional_bucket_list = input;
        self
    }
    /// <p></p>
    pub fn get_regional_bucket_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RegionalBucket>> {
        &self.regional_bucket_list
    }
    /// <p><code>NextToken</code> is sent when <code>isTruncated</code> is true, which means there are more buckets that can be listed. The next list requests to Amazon S3 can be continued with this <code>NextToken</code>. <code>NextToken</code> is obfuscated and is not a real key.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><code>NextToken</code> is sent when <code>isTruncated</code> is true, which means there are more buckets that can be listed. The next list requests to Amazon S3 can be continued with this <code>NextToken</code>. <code>NextToken</code> is obfuscated and is not a real key.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p><code>NextToken</code> is sent when <code>isTruncated</code> is true, which means there are more buckets that can be listed. The next list requests to Amazon S3 can be continued with this <code>NextToken</code>. <code>NextToken</code> is obfuscated and is not a real key.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListRegionalBucketsOutput`](crate::operation::list_regional_buckets::ListRegionalBucketsOutput).
    pub fn build(self) -> crate::operation::list_regional_buckets::ListRegionalBucketsOutput {
        crate::operation::list_regional_buckets::ListRegionalBucketsOutput {
            regional_bucket_list: self.regional_bucket_list,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
