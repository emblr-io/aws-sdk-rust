// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListOriginEndpointsInput {
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    pub channel_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    pub channel_name: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token from the GET list request. Use the token to fetch the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListOriginEndpointsInput {
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    pub fn channel_group_name(&self) -> ::std::option::Option<&str> {
        self.channel_group_name.as_deref()
    }
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    pub fn channel_name(&self) -> ::std::option::Option<&str> {
        self.channel_name.as_deref()
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token from the GET list request. Use the token to fetch the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListOriginEndpointsInput {
    /// Creates a new builder-style object to manufacture [`ListOriginEndpointsInput`](crate::operation::list_origin_endpoints::ListOriginEndpointsInput).
    pub fn builder() -> crate::operation::list_origin_endpoints::builders::ListOriginEndpointsInputBuilder {
        crate::operation::list_origin_endpoints::builders::ListOriginEndpointsInputBuilder::default()
    }
}

/// A builder for [`ListOriginEndpointsInput`](crate::operation::list_origin_endpoints::ListOriginEndpointsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListOriginEndpointsInputBuilder {
    pub(crate) channel_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) channel_name: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListOriginEndpointsInputBuilder {
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    /// This field is required.
    pub fn channel_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    pub fn set_channel_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_group_name = input;
        self
    }
    /// <p>The name that describes the channel group. The name is the primary identifier for the channel group, and must be unique for your account in the AWS Region.</p>
    pub fn get_channel_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_group_name
    }
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    /// This field is required.
    pub fn channel_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    pub fn set_channel_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_name = input;
        self
    }
    /// <p>The name that describes the channel. The name is the primary identifier for the channel, and must be unique for your account in the AWS Region and channel group.</p>
    pub fn get_channel_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_name
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token from the GET list request. Use the token to fetch the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token from the GET list request. Use the token to fetch the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token from the GET list request. Use the token to fetch the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListOriginEndpointsInput`](crate::operation::list_origin_endpoints::ListOriginEndpointsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_origin_endpoints::ListOriginEndpointsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_origin_endpoints::ListOriginEndpointsInput {
            channel_group_name: self.channel_group_name,
            channel_name: self.channel_name,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
