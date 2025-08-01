// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>ListGitHubAccountTokenNames</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListGitHubAccountTokenNamesInput {
    /// <p>An identifier returned from the previous <code>ListGitHubAccountTokenNames</code> call. It can be used to return the next set of names in the list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListGitHubAccountTokenNamesInput {
    /// <p>An identifier returned from the previous <code>ListGitHubAccountTokenNames</code> call. It can be used to return the next set of names in the list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListGitHubAccountTokenNamesInput {
    /// Creates a new builder-style object to manufacture [`ListGitHubAccountTokenNamesInput`](crate::operation::list_git_hub_account_token_names::ListGitHubAccountTokenNamesInput).
    pub fn builder() -> crate::operation::list_git_hub_account_token_names::builders::ListGitHubAccountTokenNamesInputBuilder {
        crate::operation::list_git_hub_account_token_names::builders::ListGitHubAccountTokenNamesInputBuilder::default()
    }
}

/// A builder for [`ListGitHubAccountTokenNamesInput`](crate::operation::list_git_hub_account_token_names::ListGitHubAccountTokenNamesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListGitHubAccountTokenNamesInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListGitHubAccountTokenNamesInputBuilder {
    /// <p>An identifier returned from the previous <code>ListGitHubAccountTokenNames</code> call. It can be used to return the next set of names in the list.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier returned from the previous <code>ListGitHubAccountTokenNames</code> call. It can be used to return the next set of names in the list.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An identifier returned from the previous <code>ListGitHubAccountTokenNames</code> call. It can be used to return the next set of names in the list.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListGitHubAccountTokenNamesInput`](crate::operation::list_git_hub_account_token_names::ListGitHubAccountTokenNamesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_git_hub_account_token_names::ListGitHubAccountTokenNamesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_git_hub_account_token_names::ListGitHubAccountTokenNamesInput {
            next_token: self.next_token,
        })
    }
}
