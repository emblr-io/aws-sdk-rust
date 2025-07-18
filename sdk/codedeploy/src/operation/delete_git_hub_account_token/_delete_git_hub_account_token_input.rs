// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>DeleteGitHubAccount</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteGitHubAccountTokenInput {
    /// <p>The name of the GitHub account connection to delete.</p>
    pub token_name: ::std::option::Option<::std::string::String>,
}
impl DeleteGitHubAccountTokenInput {
    /// <p>The name of the GitHub account connection to delete.</p>
    pub fn token_name(&self) -> ::std::option::Option<&str> {
        self.token_name.as_deref()
    }
}
impl DeleteGitHubAccountTokenInput {
    /// Creates a new builder-style object to manufacture [`DeleteGitHubAccountTokenInput`](crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenInput).
    pub fn builder() -> crate::operation::delete_git_hub_account_token::builders::DeleteGitHubAccountTokenInputBuilder {
        crate::operation::delete_git_hub_account_token::builders::DeleteGitHubAccountTokenInputBuilder::default()
    }
}

/// A builder for [`DeleteGitHubAccountTokenInput`](crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteGitHubAccountTokenInputBuilder {
    pub(crate) token_name: ::std::option::Option<::std::string::String>,
}
impl DeleteGitHubAccountTokenInputBuilder {
    /// <p>The name of the GitHub account connection to delete.</p>
    pub fn token_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the GitHub account connection to delete.</p>
    pub fn set_token_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token_name = input;
        self
    }
    /// <p>The name of the GitHub account connection to delete.</p>
    pub fn get_token_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.token_name
    }
    /// Consumes the builder and constructs a [`DeleteGitHubAccountTokenInput`](crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenInput { token_name: self.token_name })
    }
}
