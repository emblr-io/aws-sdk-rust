// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request object for <code>ListTagsForResource</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTagsForResourceInput {
    /// <p>The ARN of the Amazon FSx resource that will have its tags listed.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of tags to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Opaque pagination token returned from a previous <code>ListTagsForResource</code> operation (String). If a token present, the action continues the list from where the returning call left off.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListTagsForResourceInput {
    /// <p>The ARN of the Amazon FSx resource that will have its tags listed.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>Maximum number of tags to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Opaque pagination token returned from a previous <code>ListTagsForResource</code> operation (String). If a token present, the action continues the list from where the returning call left off.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListTagsForResourceInput {
    /// Creates a new builder-style object to manufacture [`ListTagsForResourceInput`](crate::operation::list_tags_for_resource::ListTagsForResourceInput).
    pub fn builder() -> crate::operation::list_tags_for_resource::builders::ListTagsForResourceInputBuilder {
        crate::operation::list_tags_for_resource::builders::ListTagsForResourceInputBuilder::default()
    }
}

/// A builder for [`ListTagsForResourceInput`](crate::operation::list_tags_for_resource::ListTagsForResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTagsForResourceInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListTagsForResourceInputBuilder {
    /// <p>The ARN of the Amazon FSx resource that will have its tags listed.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Amazon FSx resource that will have its tags listed.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The ARN of the Amazon FSx resource that will have its tags listed.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>Maximum number of tags to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of tags to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of tags to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Opaque pagination token returned from a previous <code>ListTagsForResource</code> operation (String). If a token present, the action continues the list from where the returning call left off.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Opaque pagination token returned from a previous <code>ListTagsForResource</code> operation (String). If a token present, the action continues the list from where the returning call left off.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Opaque pagination token returned from a previous <code>ListTagsForResource</code> operation (String). If a token present, the action continues the list from where the returning call left off.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListTagsForResourceInput`](crate::operation::list_tags_for_resource::ListTagsForResourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_tags_for_resource::ListTagsForResourceInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_tags_for_resource::ListTagsForResourceInput {
            resource_arn: self.resource_arn,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
