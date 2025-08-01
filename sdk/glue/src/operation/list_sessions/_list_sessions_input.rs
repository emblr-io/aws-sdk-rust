// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSessionsInput {
    /// <p>The token for the next set of results, or null if there are no more result.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Tags belonging to the session.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The origin of the request.</p>
    pub request_origin: ::std::option::Option<::std::string::String>,
}
impl ListSessionsInput {
    /// <p>The token for the next set of results, or null if there are no more result.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Tags belonging to the session.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The origin of the request.</p>
    pub fn request_origin(&self) -> ::std::option::Option<&str> {
        self.request_origin.as_deref()
    }
}
impl ListSessionsInput {
    /// Creates a new builder-style object to manufacture [`ListSessionsInput`](crate::operation::list_sessions::ListSessionsInput).
    pub fn builder() -> crate::operation::list_sessions::builders::ListSessionsInputBuilder {
        crate::operation::list_sessions::builders::ListSessionsInputBuilder::default()
    }
}

/// A builder for [`ListSessionsInput`](crate::operation::list_sessions::ListSessionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSessionsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) request_origin: ::std::option::Option<::std::string::String>,
}
impl ListSessionsInputBuilder {
    /// <p>The token for the next set of results, or null if there are no more result.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or null if there are no more result.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or null if there are no more result.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags belonging to the session.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags belonging to the session.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags belonging to the session.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The origin of the request.</p>
    pub fn request_origin(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_origin = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The origin of the request.</p>
    pub fn set_request_origin(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_origin = input;
        self
    }
    /// <p>The origin of the request.</p>
    pub fn get_request_origin(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_origin
    }
    /// Consumes the builder and constructs a [`ListSessionsInput`](crate::operation::list_sessions::ListSessionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_sessions::ListSessionsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_sessions::ListSessionsInput {
            next_token: self.next_token,
            max_results: self.max_results,
            tags: self.tags,
            request_origin: self.request_origin,
        })
    }
}
