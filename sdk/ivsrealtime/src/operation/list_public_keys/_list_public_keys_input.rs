// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPublicKeysInput {
    /// <p>The first public key to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListPublicKeysInput {
    /// <p>The first public key to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListPublicKeysInput {
    /// Creates a new builder-style object to manufacture [`ListPublicKeysInput`](crate::operation::list_public_keys::ListPublicKeysInput).
    pub fn builder() -> crate::operation::list_public_keys::builders::ListPublicKeysInputBuilder {
        crate::operation::list_public_keys::builders::ListPublicKeysInputBuilder::default()
    }
}

/// A builder for [`ListPublicKeysInput`](crate::operation::list_public_keys::ListPublicKeysInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPublicKeysInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListPublicKeysInputBuilder {
    /// <p>The first public key to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The first public key to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The first public key to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListPublicKeysInput`](crate::operation::list_public_keys::ListPublicKeysInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_public_keys::ListPublicKeysInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_public_keys::ListPublicKeysInput {
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
