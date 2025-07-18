// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEcsServiceRecommendationsInput {
    /// <p>The ARN that identifies the Amazon ECS service.</p>
    /// <p>The following is the format of the ARN:</p>
    /// <p><code>arn:aws:ecs:region:aws_account_id:service/cluster-name/service-name</code></p>
    pub service_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The token to advance to the next page of Amazon ECS service recommendations.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of Amazon ECS service recommendations to return with a single request.</p>
    /// <p>To retrieve the remaining results, make another request with the returned <code>nextToken</code> value.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>An array of objects to specify a filter that returns a more specific list of Amazon ECS service recommendations.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::EcsServiceRecommendationFilter>>,
    /// <p>Return the Amazon ECS service recommendations to the specified Amazon Web Services account IDs.</p>
    /// <p>If your account is the management account or the delegated administrator of an organization, use this parameter to return the Amazon ECS service recommendations to specific member accounts.</p>
    /// <p>You can only specify one account ID per request.</p>
    pub account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetEcsServiceRecommendationsInput {
    /// <p>The ARN that identifies the Amazon ECS service.</p>
    /// <p>The following is the format of the ARN:</p>
    /// <p><code>arn:aws:ecs:region:aws_account_id:service/cluster-name/service-name</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.service_arns.is_none()`.
    pub fn service_arns(&self) -> &[::std::string::String] {
        self.service_arns.as_deref().unwrap_or_default()
    }
    /// <p>The token to advance to the next page of Amazon ECS service recommendations.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of Amazon ECS service recommendations to return with a single request.</p>
    /// <p>To retrieve the remaining results, make another request with the returned <code>nextToken</code> value.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>An array of objects to specify a filter that returns a more specific list of Amazon ECS service recommendations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::EcsServiceRecommendationFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>Return the Amazon ECS service recommendations to the specified Amazon Web Services account IDs.</p>
    /// <p>If your account is the management account or the delegated administrator of an organization, use this parameter to return the Amazon ECS service recommendations to specific member accounts.</p>
    /// <p>You can only specify one account ID per request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.account_ids.is_none()`.
    pub fn account_ids(&self) -> &[::std::string::String] {
        self.account_ids.as_deref().unwrap_or_default()
    }
}
impl GetEcsServiceRecommendationsInput {
    /// Creates a new builder-style object to manufacture [`GetEcsServiceRecommendationsInput`](crate::operation::get_ecs_service_recommendations::GetEcsServiceRecommendationsInput).
    pub fn builder() -> crate::operation::get_ecs_service_recommendations::builders::GetEcsServiceRecommendationsInputBuilder {
        crate::operation::get_ecs_service_recommendations::builders::GetEcsServiceRecommendationsInputBuilder::default()
    }
}

/// A builder for [`GetEcsServiceRecommendationsInput`](crate::operation::get_ecs_service_recommendations::GetEcsServiceRecommendationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEcsServiceRecommendationsInputBuilder {
    pub(crate) service_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::EcsServiceRecommendationFilter>>,
    pub(crate) account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetEcsServiceRecommendationsInputBuilder {
    /// Appends an item to `service_arns`.
    ///
    /// To override the contents of this collection use [`set_service_arns`](Self::set_service_arns).
    ///
    /// <p>The ARN that identifies the Amazon ECS service.</p>
    /// <p>The following is the format of the ARN:</p>
    /// <p><code>arn:aws:ecs:region:aws_account_id:service/cluster-name/service-name</code></p>
    pub fn service_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.service_arns.unwrap_or_default();
        v.push(input.into());
        self.service_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARN that identifies the Amazon ECS service.</p>
    /// <p>The following is the format of the ARN:</p>
    /// <p><code>arn:aws:ecs:region:aws_account_id:service/cluster-name/service-name</code></p>
    pub fn set_service_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.service_arns = input;
        self
    }
    /// <p>The ARN that identifies the Amazon ECS service.</p>
    /// <p>The following is the format of the ARN:</p>
    /// <p><code>arn:aws:ecs:region:aws_account_id:service/cluster-name/service-name</code></p>
    pub fn get_service_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.service_arns
    }
    /// <p>The token to advance to the next page of Amazon ECS service recommendations.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to advance to the next page of Amazon ECS service recommendations.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to advance to the next page of Amazon ECS service recommendations.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of Amazon ECS service recommendations to return with a single request.</p>
    /// <p>To retrieve the remaining results, make another request with the returned <code>nextToken</code> value.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of Amazon ECS service recommendations to return with a single request.</p>
    /// <p>To retrieve the remaining results, make another request with the returned <code>nextToken</code> value.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of Amazon ECS service recommendations to return with a single request.</p>
    /// <p>To retrieve the remaining results, make another request with the returned <code>nextToken</code> value.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>An array of objects to specify a filter that returns a more specific list of Amazon ECS service recommendations.</p>
    pub fn filters(mut self, input: crate::types::EcsServiceRecommendationFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects to specify a filter that returns a more specific list of Amazon ECS service recommendations.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EcsServiceRecommendationFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>An array of objects to specify a filter that returns a more specific list of Amazon ECS service recommendations.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EcsServiceRecommendationFilter>> {
        &self.filters
    }
    /// Appends an item to `account_ids`.
    ///
    /// To override the contents of this collection use [`set_account_ids`](Self::set_account_ids).
    ///
    /// <p>Return the Amazon ECS service recommendations to the specified Amazon Web Services account IDs.</p>
    /// <p>If your account is the management account or the delegated administrator of an organization, use this parameter to return the Amazon ECS service recommendations to specific member accounts.</p>
    /// <p>You can only specify one account ID per request.</p>
    pub fn account_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.account_ids.unwrap_or_default();
        v.push(input.into());
        self.account_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Return the Amazon ECS service recommendations to the specified Amazon Web Services account IDs.</p>
    /// <p>If your account is the management account or the delegated administrator of an organization, use this parameter to return the Amazon ECS service recommendations to specific member accounts.</p>
    /// <p>You can only specify one account ID per request.</p>
    pub fn set_account_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.account_ids = input;
        self
    }
    /// <p>Return the Amazon ECS service recommendations to the specified Amazon Web Services account IDs.</p>
    /// <p>If your account is the management account or the delegated administrator of an organization, use this parameter to return the Amazon ECS service recommendations to specific member accounts.</p>
    /// <p>You can only specify one account ID per request.</p>
    pub fn get_account_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.account_ids
    }
    /// Consumes the builder and constructs a [`GetEcsServiceRecommendationsInput`](crate::operation::get_ecs_service_recommendations::GetEcsServiceRecommendationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_ecs_service_recommendations::GetEcsServiceRecommendationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_ecs_service_recommendations::GetEcsServiceRecommendationsInput {
            service_arns: self.service_arns,
            next_token: self.next_token,
            max_results: self.max_results,
            filters: self.filters,
            account_ids: self.account_ids,
        })
    }
}
