// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListBotVersionsInput {
    /// <p>The identifier of the bot to list versions for.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies sorting parameters for the list of versions. You can specify that the list be sorted by version name in either ascending or descending order.</p>
    pub sort_by: ::std::option::Option<crate::types::BotVersionSortBy>,
    /// <p>The maximum number of versions to return in each page of results. If there are fewer results than the max page size, only the actual number of results are returned.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>If the response to the <code>ListBotVersion</code> operation contains more results than specified in the <code>maxResults</code> parameter, a token is returned in the response. Use that token in the <code>nextToken</code> parameter to return the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListBotVersionsInput {
    /// <p>The identifier of the bot to list versions for.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>Specifies sorting parameters for the list of versions. You can specify that the list be sorted by version name in either ascending or descending order.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::BotVersionSortBy> {
        self.sort_by.as_ref()
    }
    /// <p>The maximum number of versions to return in each page of results. If there are fewer results than the max page size, only the actual number of results are returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>If the response to the <code>ListBotVersion</code> operation contains more results than specified in the <code>maxResults</code> parameter, a token is returned in the response. Use that token in the <code>nextToken</code> parameter to return the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListBotVersionsInput {
    /// Creates a new builder-style object to manufacture [`ListBotVersionsInput`](crate::operation::list_bot_versions::ListBotVersionsInput).
    pub fn builder() -> crate::operation::list_bot_versions::builders::ListBotVersionsInputBuilder {
        crate::operation::list_bot_versions::builders::ListBotVersionsInputBuilder::default()
    }
}

/// A builder for [`ListBotVersionsInput`](crate::operation::list_bot_versions::ListBotVersionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListBotVersionsInputBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) sort_by: ::std::option::Option<crate::types::BotVersionSortBy>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListBotVersionsInputBuilder {
    /// <p>The identifier of the bot to list versions for.</p>
    /// This field is required.
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the bot to list versions for.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The identifier of the bot to list versions for.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>Specifies sorting parameters for the list of versions. You can specify that the list be sorted by version name in either ascending or descending order.</p>
    pub fn sort_by(mut self, input: crate::types::BotVersionSortBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies sorting parameters for the list of versions. You can specify that the list be sorted by version name in either ascending or descending order.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::BotVersionSortBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>Specifies sorting parameters for the list of versions. You can specify that the list be sorted by version name in either ascending or descending order.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::BotVersionSortBy> {
        &self.sort_by
    }
    /// <p>The maximum number of versions to return in each page of results. If there are fewer results than the max page size, only the actual number of results are returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of versions to return in each page of results. If there are fewer results than the max page size, only the actual number of results are returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of versions to return in each page of results. If there are fewer results than the max page size, only the actual number of results are returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>If the response to the <code>ListBotVersion</code> operation contains more results than specified in the <code>maxResults</code> parameter, a token is returned in the response. Use that token in the <code>nextToken</code> parameter to return the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response to the <code>ListBotVersion</code> operation contains more results than specified in the <code>maxResults</code> parameter, a token is returned in the response. Use that token in the <code>nextToken</code> parameter to return the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response to the <code>ListBotVersion</code> operation contains more results than specified in the <code>maxResults</code> parameter, a token is returned in the response. Use that token in the <code>nextToken</code> parameter to return the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListBotVersionsInput`](crate::operation::list_bot_versions::ListBotVersionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_bot_versions::ListBotVersionsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_bot_versions::ListBotVersionsInput {
            bot_id: self.bot_id,
            sort_by: self.sort_by,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
