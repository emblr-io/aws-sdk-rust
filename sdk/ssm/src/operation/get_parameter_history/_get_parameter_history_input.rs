// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetParameterHistoryInput {
    /// <p>The name or Amazon Resource Name (ARN) of the parameter for which you want to review history. For parameters shared with you from another account, you must use the full ARN.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Return decrypted values for secure string parameters. This flag is ignored for <code>String</code> and <code>StringList</code> parameter types.</p>
    pub with_decryption: ::std::option::Option<bool>,
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetParameterHistoryInput {
    /// <p>The name or Amazon Resource Name (ARN) of the parameter for which you want to review history. For parameters shared with you from another account, you must use the full ARN.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Return decrypted values for secure string parameters. This flag is ignored for <code>String</code> and <code>StringList</code> parameter types.</p>
    pub fn with_decryption(&self) -> ::std::option::Option<bool> {
        self.with_decryption
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetParameterHistoryInput {
    /// Creates a new builder-style object to manufacture [`GetParameterHistoryInput`](crate::operation::get_parameter_history::GetParameterHistoryInput).
    pub fn builder() -> crate::operation::get_parameter_history::builders::GetParameterHistoryInputBuilder {
        crate::operation::get_parameter_history::builders::GetParameterHistoryInputBuilder::default()
    }
}

/// A builder for [`GetParameterHistoryInput`](crate::operation::get_parameter_history::GetParameterHistoryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetParameterHistoryInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) with_decryption: ::std::option::Option<bool>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetParameterHistoryInputBuilder {
    /// <p>The name or Amazon Resource Name (ARN) of the parameter for which you want to review history. For parameters shared with you from another account, you must use the full ARN.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the parameter for which you want to review history. For parameters shared with you from another account, you must use the full ARN.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the parameter for which you want to review history. For parameters shared with you from another account, you must use the full ARN.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Return decrypted values for secure string parameters. This flag is ignored for <code>String</code> and <code>StringList</code> parameter types.</p>
    pub fn with_decryption(mut self, input: bool) -> Self {
        self.with_decryption = ::std::option::Option::Some(input);
        self
    }
    /// <p>Return decrypted values for secure string parameters. This flag is ignored for <code>String</code> and <code>StringList</code> parameter types.</p>
    pub fn set_with_decryption(mut self, input: ::std::option::Option<bool>) -> Self {
        self.with_decryption = input;
        self
    }
    /// <p>Return decrypted values for secure string parameters. This flag is ignored for <code>String</code> and <code>StringList</code> parameter types.</p>
    pub fn get_with_decryption(&self) -> &::std::option::Option<bool> {
        &self.with_decryption
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetParameterHistoryInput`](crate::operation::get_parameter_history::GetParameterHistoryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_parameter_history::GetParameterHistoryInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_parameter_history::GetParameterHistoryInput {
            name: self.name,
            with_decryption: self.with_decryption,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
