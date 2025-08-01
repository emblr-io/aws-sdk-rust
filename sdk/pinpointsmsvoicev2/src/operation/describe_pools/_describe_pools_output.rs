// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribePoolsOutput {
    /// <p>An array of PoolInformation objects that contain the details for the requested pools.</p>
    pub pools: ::std::option::Option<::std::vec::Vec<crate::types::PoolInformation>>,
    /// <p>The token to be used for the next set of paginated results. If this field is empty then there are no more results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribePoolsOutput {
    /// <p>An array of PoolInformation objects that contain the details for the requested pools.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.pools.is_none()`.
    pub fn pools(&self) -> &[crate::types::PoolInformation] {
        self.pools.as_deref().unwrap_or_default()
    }
    /// <p>The token to be used for the next set of paginated results. If this field is empty then there are no more results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribePoolsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribePoolsOutput {
    /// Creates a new builder-style object to manufacture [`DescribePoolsOutput`](crate::operation::describe_pools::DescribePoolsOutput).
    pub fn builder() -> crate::operation::describe_pools::builders::DescribePoolsOutputBuilder {
        crate::operation::describe_pools::builders::DescribePoolsOutputBuilder::default()
    }
}

/// A builder for [`DescribePoolsOutput`](crate::operation::describe_pools::DescribePoolsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribePoolsOutputBuilder {
    pub(crate) pools: ::std::option::Option<::std::vec::Vec<crate::types::PoolInformation>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribePoolsOutputBuilder {
    /// Appends an item to `pools`.
    ///
    /// To override the contents of this collection use [`set_pools`](Self::set_pools).
    ///
    /// <p>An array of PoolInformation objects that contain the details for the requested pools.</p>
    pub fn pools(mut self, input: crate::types::PoolInformation) -> Self {
        let mut v = self.pools.unwrap_or_default();
        v.push(input);
        self.pools = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of PoolInformation objects that contain the details for the requested pools.</p>
    pub fn set_pools(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PoolInformation>>) -> Self {
        self.pools = input;
        self
    }
    /// <p>An array of PoolInformation objects that contain the details for the requested pools.</p>
    pub fn get_pools(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PoolInformation>> {
        &self.pools
    }
    /// <p>The token to be used for the next set of paginated results. If this field is empty then there are no more results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to be used for the next set of paginated results. If this field is empty then there are no more results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to be used for the next set of paginated results. If this field is empty then there are no more results.</p>
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
    /// Consumes the builder and constructs a [`DescribePoolsOutput`](crate::operation::describe_pools::DescribePoolsOutput).
    pub fn build(self) -> crate::operation::describe_pools::DescribePoolsOutput {
        crate::operation::describe_pools::DescribePoolsOutput {
            pools: self.pools,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
