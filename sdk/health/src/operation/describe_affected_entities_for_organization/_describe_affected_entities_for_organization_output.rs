// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAffectedEntitiesForOrganizationOutput {
    /// <p>A JSON set of elements including the <code>awsAccountId</code> and its <code>entityArn</code>, <code>entityValue</code> and its <code>entityArn</code>, <code>lastUpdatedTime</code>, and <code>statusCode</code>.</p>
    pub entities: ::std::option::Option<::std::vec::Vec<crate::types::AffectedEntity>>,
    /// <p>A JSON set of elements of the failed response, including the <code>awsAccountId</code>, <code>errorMessage</code>, <code>errorName</code>, and <code>eventArn</code>.</p>
    pub failed_set: ::std::option::Option<::std::vec::Vec<crate::types::OrganizationAffectedEntitiesErrorItem>>,
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next batch of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeAffectedEntitiesForOrganizationOutput {
    /// <p>A JSON set of elements including the <code>awsAccountId</code> and its <code>entityArn</code>, <code>entityValue</code> and its <code>entityArn</code>, <code>lastUpdatedTime</code>, and <code>statusCode</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.entities.is_none()`.
    pub fn entities(&self) -> &[crate::types::AffectedEntity] {
        self.entities.as_deref().unwrap_or_default()
    }
    /// <p>A JSON set of elements of the failed response, including the <code>awsAccountId</code>, <code>errorMessage</code>, <code>errorName</code>, and <code>eventArn</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failed_set.is_none()`.
    pub fn failed_set(&self) -> &[crate::types::OrganizationAffectedEntitiesErrorItem] {
        self.failed_set.as_deref().unwrap_or_default()
    }
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next batch of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeAffectedEntitiesForOrganizationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeAffectedEntitiesForOrganizationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeAffectedEntitiesForOrganizationOutput`](crate::operation::describe_affected_entities_for_organization::DescribeAffectedEntitiesForOrganizationOutput).
    pub fn builder() -> crate::operation::describe_affected_entities_for_organization::builders::DescribeAffectedEntitiesForOrganizationOutputBuilder
    {
        crate::operation::describe_affected_entities_for_organization::builders::DescribeAffectedEntitiesForOrganizationOutputBuilder::default()
    }
}

/// A builder for [`DescribeAffectedEntitiesForOrganizationOutput`](crate::operation::describe_affected_entities_for_organization::DescribeAffectedEntitiesForOrganizationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAffectedEntitiesForOrganizationOutputBuilder {
    pub(crate) entities: ::std::option::Option<::std::vec::Vec<crate::types::AffectedEntity>>,
    pub(crate) failed_set: ::std::option::Option<::std::vec::Vec<crate::types::OrganizationAffectedEntitiesErrorItem>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeAffectedEntitiesForOrganizationOutputBuilder {
    /// Appends an item to `entities`.
    ///
    /// To override the contents of this collection use [`set_entities`](Self::set_entities).
    ///
    /// <p>A JSON set of elements including the <code>awsAccountId</code> and its <code>entityArn</code>, <code>entityValue</code> and its <code>entityArn</code>, <code>lastUpdatedTime</code>, and <code>statusCode</code>.</p>
    pub fn entities(mut self, input: crate::types::AffectedEntity) -> Self {
        let mut v = self.entities.unwrap_or_default();
        v.push(input);
        self.entities = ::std::option::Option::Some(v);
        self
    }
    /// <p>A JSON set of elements including the <code>awsAccountId</code> and its <code>entityArn</code>, <code>entityValue</code> and its <code>entityArn</code>, <code>lastUpdatedTime</code>, and <code>statusCode</code>.</p>
    pub fn set_entities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AffectedEntity>>) -> Self {
        self.entities = input;
        self
    }
    /// <p>A JSON set of elements including the <code>awsAccountId</code> and its <code>entityArn</code>, <code>entityValue</code> and its <code>entityArn</code>, <code>lastUpdatedTime</code>, and <code>statusCode</code>.</p>
    pub fn get_entities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AffectedEntity>> {
        &self.entities
    }
    /// Appends an item to `failed_set`.
    ///
    /// To override the contents of this collection use [`set_failed_set`](Self::set_failed_set).
    ///
    /// <p>A JSON set of elements of the failed response, including the <code>awsAccountId</code>, <code>errorMessage</code>, <code>errorName</code>, and <code>eventArn</code>.</p>
    pub fn failed_set(mut self, input: crate::types::OrganizationAffectedEntitiesErrorItem) -> Self {
        let mut v = self.failed_set.unwrap_or_default();
        v.push(input);
        self.failed_set = ::std::option::Option::Some(v);
        self
    }
    /// <p>A JSON set of elements of the failed response, including the <code>awsAccountId</code>, <code>errorMessage</code>, <code>errorName</code>, and <code>eventArn</code>.</p>
    pub fn set_failed_set(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OrganizationAffectedEntitiesErrorItem>>) -> Self {
        self.failed_set = input;
        self
    }
    /// <p>A JSON set of elements of the failed response, including the <code>awsAccountId</code>, <code>errorMessage</code>, <code>errorName</code>, and <code>eventArn</code>.</p>
    pub fn get_failed_set(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OrganizationAffectedEntitiesErrorItem>> {
        &self.failed_set
    }
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next batch of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next batch of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the results of a search are large, only a portion of the results are returned, and a <code>nextToken</code> pagination token is returned in the response. To retrieve the next batch of results, reissue the search request and include the returned token. When all results have been returned, the response does not contain a pagination token value.</p>
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
    /// Consumes the builder and constructs a [`DescribeAffectedEntitiesForOrganizationOutput`](crate::operation::describe_affected_entities_for_organization::DescribeAffectedEntitiesForOrganizationOutput).
    pub fn build(self) -> crate::operation::describe_affected_entities_for_organization::DescribeAffectedEntitiesForOrganizationOutput {
        crate::operation::describe_affected_entities_for_organization::DescribeAffectedEntitiesForOrganizationOutput {
            entities: self.entities,
            failed_set: self.failed_set,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
