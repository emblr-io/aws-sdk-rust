// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>DeleteGitHubAccountToken</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteGitHubAccountTokenOutput {
    /// <p>The name of the GitHub account connection that was deleted.</p>
    pub token_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteGitHubAccountTokenOutput {
    /// <p>The name of the GitHub account connection that was deleted.</p>
    pub fn token_name(&self) -> ::std::option::Option<&str> {
        self.token_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteGitHubAccountTokenOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteGitHubAccountTokenOutput {
    /// Creates a new builder-style object to manufacture [`DeleteGitHubAccountTokenOutput`](crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenOutput).
    pub fn builder() -> crate::operation::delete_git_hub_account_token::builders::DeleteGitHubAccountTokenOutputBuilder {
        crate::operation::delete_git_hub_account_token::builders::DeleteGitHubAccountTokenOutputBuilder::default()
    }
}

/// A builder for [`DeleteGitHubAccountTokenOutput`](crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteGitHubAccountTokenOutputBuilder {
    pub(crate) token_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteGitHubAccountTokenOutputBuilder {
    /// <p>The name of the GitHub account connection that was deleted.</p>
    pub fn token_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the GitHub account connection that was deleted.</p>
    pub fn set_token_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token_name = input;
        self
    }
    /// <p>The name of the GitHub account connection that was deleted.</p>
    pub fn get_token_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.token_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteGitHubAccountTokenOutput`](crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenOutput).
    pub fn build(self) -> crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenOutput {
        crate::operation::delete_git_hub_account_token::DeleteGitHubAccountTokenOutput {
            token_name: self.token_name,
            _request_id: self._request_id,
        }
    }
}
