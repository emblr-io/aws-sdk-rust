// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeRecommendationLimitationsOutput {
    /// <p>The unique pagination token returned for you to pass to a subsequent request. Fleet Advisor returns this token when the number of records in the response is greater than the <code>MaxRecords</code> value. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The list of limitations for recommendations of target Amazon Web Services engines.</p>
    pub limitations: ::std::option::Option<::std::vec::Vec<crate::types::Limitation>>,
    _request_id: Option<String>,
}
impl DescribeRecommendationLimitationsOutput {
    /// <p>The unique pagination token returned for you to pass to a subsequent request. Fleet Advisor returns this token when the number of records in the response is greater than the <code>MaxRecords</code> value. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The list of limitations for recommendations of target Amazon Web Services engines.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.limitations.is_none()`.
    pub fn limitations(&self) -> &[crate::types::Limitation] {
        self.limitations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeRecommendationLimitationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeRecommendationLimitationsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeRecommendationLimitationsOutput`](crate::operation::describe_recommendation_limitations::DescribeRecommendationLimitationsOutput).
    pub fn builder() -> crate::operation::describe_recommendation_limitations::builders::DescribeRecommendationLimitationsOutputBuilder {
        crate::operation::describe_recommendation_limitations::builders::DescribeRecommendationLimitationsOutputBuilder::default()
    }
}

/// A builder for [`DescribeRecommendationLimitationsOutput`](crate::operation::describe_recommendation_limitations::DescribeRecommendationLimitationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeRecommendationLimitationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) limitations: ::std::option::Option<::std::vec::Vec<crate::types::Limitation>>,
    _request_id: Option<String>,
}
impl DescribeRecommendationLimitationsOutputBuilder {
    /// <p>The unique pagination token returned for you to pass to a subsequent request. Fleet Advisor returns this token when the number of records in the response is greater than the <code>MaxRecords</code> value. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique pagination token returned for you to pass to a subsequent request. Fleet Advisor returns this token when the number of records in the response is greater than the <code>MaxRecords</code> value. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The unique pagination token returned for you to pass to a subsequent request. Fleet Advisor returns this token when the number of records in the response is greater than the <code>MaxRecords</code> value. To retrieve the next page, make the call again using the returned token and keeping all other arguments unchanged.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `limitations`.
    ///
    /// To override the contents of this collection use [`set_limitations`](Self::set_limitations).
    ///
    /// <p>The list of limitations for recommendations of target Amazon Web Services engines.</p>
    pub fn limitations(mut self, input: crate::types::Limitation) -> Self {
        let mut v = self.limitations.unwrap_or_default();
        v.push(input);
        self.limitations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of limitations for recommendations of target Amazon Web Services engines.</p>
    pub fn set_limitations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Limitation>>) -> Self {
        self.limitations = input;
        self
    }
    /// <p>The list of limitations for recommendations of target Amazon Web Services engines.</p>
    pub fn get_limitations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Limitation>> {
        &self.limitations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeRecommendationLimitationsOutput`](crate::operation::describe_recommendation_limitations::DescribeRecommendationLimitationsOutput).
    pub fn build(self) -> crate::operation::describe_recommendation_limitations::DescribeRecommendationLimitationsOutput {
        crate::operation::describe_recommendation_limitations::DescribeRecommendationLimitationsOutput {
            next_token: self.next_token,
            limitations: self.limitations,
            _request_id: self._request_id,
        }
    }
}
