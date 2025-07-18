// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAggregationAuthorizationsOutput {
    /// <p>Returns a list of authorizations granted to various aggregator accounts and regions.</p>
    pub aggregation_authorizations: ::std::option::Option<::std::vec::Vec<crate::types::AggregationAuthorization>>,
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeAggregationAuthorizationsOutput {
    /// <p>Returns a list of authorizations granted to various aggregator accounts and regions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.aggregation_authorizations.is_none()`.
    pub fn aggregation_authorizations(&self) -> &[crate::types::AggregationAuthorization] {
        self.aggregation_authorizations.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeAggregationAuthorizationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeAggregationAuthorizationsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeAggregationAuthorizationsOutput`](crate::operation::describe_aggregation_authorizations::DescribeAggregationAuthorizationsOutput).
    pub fn builder() -> crate::operation::describe_aggregation_authorizations::builders::DescribeAggregationAuthorizationsOutputBuilder {
        crate::operation::describe_aggregation_authorizations::builders::DescribeAggregationAuthorizationsOutputBuilder::default()
    }
}

/// A builder for [`DescribeAggregationAuthorizationsOutput`](crate::operation::describe_aggregation_authorizations::DescribeAggregationAuthorizationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAggregationAuthorizationsOutputBuilder {
    pub(crate) aggregation_authorizations: ::std::option::Option<::std::vec::Vec<crate::types::AggregationAuthorization>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeAggregationAuthorizationsOutputBuilder {
    /// Appends an item to `aggregation_authorizations`.
    ///
    /// To override the contents of this collection use [`set_aggregation_authorizations`](Self::set_aggregation_authorizations).
    ///
    /// <p>Returns a list of authorizations granted to various aggregator accounts and regions.</p>
    pub fn aggregation_authorizations(mut self, input: crate::types::AggregationAuthorization) -> Self {
        let mut v = self.aggregation_authorizations.unwrap_or_default();
        v.push(input);
        self.aggregation_authorizations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns a list of authorizations granted to various aggregator accounts and regions.</p>
    pub fn set_aggregation_authorizations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AggregationAuthorization>>) -> Self {
        self.aggregation_authorizations = input;
        self
    }
    /// <p>Returns a list of authorizations granted to various aggregator accounts and regions.</p>
    pub fn get_aggregation_authorizations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AggregationAuthorization>> {
        &self.aggregation_authorizations
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
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
    /// Consumes the builder and constructs a [`DescribeAggregationAuthorizationsOutput`](crate::operation::describe_aggregation_authorizations::DescribeAggregationAuthorizationsOutput).
    pub fn build(self) -> crate::operation::describe_aggregation_authorizations::DescribeAggregationAuthorizationsOutput {
        crate::operation::describe_aggregation_authorizations::DescribeAggregationAuthorizationsOutput {
            aggregation_authorizations: self.aggregation_authorizations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
