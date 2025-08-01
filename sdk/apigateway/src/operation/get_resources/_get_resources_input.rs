// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request to list information about a collection of resources.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourcesInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub rest_api_id: ::std::option::Option<::std::string::String>,
    /// <p>The current pagination position in the paged result set.</p>
    pub position: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>A query parameter used to retrieve the specified resources embedded in the returned Resources resource in the response. This <code>embed</code> parameter value is a list of comma-separated strings. Currently, the request supports only retrieval of the embedded Method resources this way. The query parameter value must be a single-valued list and contain the <code>"methods"</code> string. For example, <code>GET /restapis/{restapi_id}/resources?embed=methods</code>.</p>
    pub embed: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetResourcesInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn rest_api_id(&self) -> ::std::option::Option<&str> {
        self.rest_api_id.as_deref()
    }
    /// <p>The current pagination position in the paged result set.</p>
    pub fn position(&self) -> ::std::option::Option<&str> {
        self.position.as_deref()
    }
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>A query parameter used to retrieve the specified resources embedded in the returned Resources resource in the response. This <code>embed</code> parameter value is a list of comma-separated strings. Currently, the request supports only retrieval of the embedded Method resources this way. The query parameter value must be a single-valued list and contain the <code>"methods"</code> string. For example, <code>GET /restapis/{restapi_id}/resources?embed=methods</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.embed.is_none()`.
    pub fn embed(&self) -> &[::std::string::String] {
        self.embed.as_deref().unwrap_or_default()
    }
}
impl GetResourcesInput {
    /// Creates a new builder-style object to manufacture [`GetResourcesInput`](crate::operation::get_resources::GetResourcesInput).
    pub fn builder() -> crate::operation::get_resources::builders::GetResourcesInputBuilder {
        crate::operation::get_resources::builders::GetResourcesInputBuilder::default()
    }
}

/// A builder for [`GetResourcesInput`](crate::operation::get_resources::GetResourcesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourcesInputBuilder {
    pub(crate) rest_api_id: ::std::option::Option<::std::string::String>,
    pub(crate) position: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) embed: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetResourcesInputBuilder {
    /// <p>The string identifier of the associated RestApi.</p>
    /// This field is required.
    pub fn rest_api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rest_api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn set_rest_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rest_api_id = input;
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn get_rest_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rest_api_id
    }
    /// <p>The current pagination position in the paged result set.</p>
    pub fn position(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.position = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current pagination position in the paged result set.</p>
    pub fn set_position(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.position = input;
        self
    }
    /// <p>The current pagination position in the paged result set.</p>
    pub fn get_position(&self) -> &::std::option::Option<::std::string::String> {
        &self.position
    }
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// Appends an item to `embed`.
    ///
    /// To override the contents of this collection use [`set_embed`](Self::set_embed).
    ///
    /// <p>A query parameter used to retrieve the specified resources embedded in the returned Resources resource in the response. This <code>embed</code> parameter value is a list of comma-separated strings. Currently, the request supports only retrieval of the embedded Method resources this way. The query parameter value must be a single-valued list and contain the <code>"methods"</code> string. For example, <code>GET /restapis/{restapi_id}/resources?embed=methods</code>.</p>
    pub fn embed(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.embed.unwrap_or_default();
        v.push(input.into());
        self.embed = ::std::option::Option::Some(v);
        self
    }
    /// <p>A query parameter used to retrieve the specified resources embedded in the returned Resources resource in the response. This <code>embed</code> parameter value is a list of comma-separated strings. Currently, the request supports only retrieval of the embedded Method resources this way. The query parameter value must be a single-valued list and contain the <code>"methods"</code> string. For example, <code>GET /restapis/{restapi_id}/resources?embed=methods</code>.</p>
    pub fn set_embed(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.embed = input;
        self
    }
    /// <p>A query parameter used to retrieve the specified resources embedded in the returned Resources resource in the response. This <code>embed</code> parameter value is a list of comma-separated strings. Currently, the request supports only retrieval of the embedded Method resources this way. The query parameter value must be a single-valued list and contain the <code>"methods"</code> string. For example, <code>GET /restapis/{restapi_id}/resources?embed=methods</code>.</p>
    pub fn get_embed(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.embed
    }
    /// Consumes the builder and constructs a [`GetResourcesInput`](crate::operation::get_resources::GetResourcesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_resources::GetResourcesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_resources::GetResourcesInput {
            rest_api_id: self.rest_api_id,
            position: self.position,
            limit: self.limit,
            embed: self.embed,
        })
    }
}
