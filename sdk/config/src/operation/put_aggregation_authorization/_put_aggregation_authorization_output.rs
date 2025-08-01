// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAggregationAuthorizationOutput {
    /// <p>Returns an AggregationAuthorization object.</p>
    pub aggregation_authorization: ::std::option::Option<crate::types::AggregationAuthorization>,
    _request_id: Option<String>,
}
impl PutAggregationAuthorizationOutput {
    /// <p>Returns an AggregationAuthorization object.</p>
    pub fn aggregation_authorization(&self) -> ::std::option::Option<&crate::types::AggregationAuthorization> {
        self.aggregation_authorization.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutAggregationAuthorizationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutAggregationAuthorizationOutput {
    /// Creates a new builder-style object to manufacture [`PutAggregationAuthorizationOutput`](crate::operation::put_aggregation_authorization::PutAggregationAuthorizationOutput).
    pub fn builder() -> crate::operation::put_aggregation_authorization::builders::PutAggregationAuthorizationOutputBuilder {
        crate::operation::put_aggregation_authorization::builders::PutAggregationAuthorizationOutputBuilder::default()
    }
}

/// A builder for [`PutAggregationAuthorizationOutput`](crate::operation::put_aggregation_authorization::PutAggregationAuthorizationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutAggregationAuthorizationOutputBuilder {
    pub(crate) aggregation_authorization: ::std::option::Option<crate::types::AggregationAuthorization>,
    _request_id: Option<String>,
}
impl PutAggregationAuthorizationOutputBuilder {
    /// <p>Returns an AggregationAuthorization object.</p>
    pub fn aggregation_authorization(mut self, input: crate::types::AggregationAuthorization) -> Self {
        self.aggregation_authorization = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns an AggregationAuthorization object.</p>
    pub fn set_aggregation_authorization(mut self, input: ::std::option::Option<crate::types::AggregationAuthorization>) -> Self {
        self.aggregation_authorization = input;
        self
    }
    /// <p>Returns an AggregationAuthorization object.</p>
    pub fn get_aggregation_authorization(&self) -> &::std::option::Option<crate::types::AggregationAuthorization> {
        &self.aggregation_authorization
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutAggregationAuthorizationOutput`](crate::operation::put_aggregation_authorization::PutAggregationAuthorizationOutput).
    pub fn build(self) -> crate::operation::put_aggregation_authorization::PutAggregationAuthorizationOutput {
        crate::operation::put_aggregation_authorization::PutAggregationAuthorizationOutput {
            aggregation_authorization: self.aggregation_authorization,
            _request_id: self._request_id,
        }
    }
}
