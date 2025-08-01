// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a request to return a list of all identities (email addresses and domains) that you have attempted to verify under your Amazon Web Services account, regardless of verification status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListIdentitiesInput {
    /// <p>The type of the identities to list. Possible values are "EmailAddress" and "Domain". If this parameter is omitted, then all identities are listed.</p>
    pub identity_type: ::std::option::Option<crate::types::IdentityType>,
    /// <p>The token to use for pagination.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of identities per page. Possible values are 1-1000 inclusive.</p>
    pub max_items: ::std::option::Option<i32>,
}
impl ListIdentitiesInput {
    /// <p>The type of the identities to list. Possible values are "EmailAddress" and "Domain". If this parameter is omitted, then all identities are listed.</p>
    pub fn identity_type(&self) -> ::std::option::Option<&crate::types::IdentityType> {
        self.identity_type.as_ref()
    }
    /// <p>The token to use for pagination.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of identities per page. Possible values are 1-1000 inclusive.</p>
    pub fn max_items(&self) -> ::std::option::Option<i32> {
        self.max_items
    }
}
impl ListIdentitiesInput {
    /// Creates a new builder-style object to manufacture [`ListIdentitiesInput`](crate::operation::list_identities::ListIdentitiesInput).
    pub fn builder() -> crate::operation::list_identities::builders::ListIdentitiesInputBuilder {
        crate::operation::list_identities::builders::ListIdentitiesInputBuilder::default()
    }
}

/// A builder for [`ListIdentitiesInput`](crate::operation::list_identities::ListIdentitiesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListIdentitiesInputBuilder {
    pub(crate) identity_type: ::std::option::Option<crate::types::IdentityType>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
}
impl ListIdentitiesInputBuilder {
    /// <p>The type of the identities to list. Possible values are "EmailAddress" and "Domain". If this parameter is omitted, then all identities are listed.</p>
    pub fn identity_type(mut self, input: crate::types::IdentityType) -> Self {
        self.identity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the identities to list. Possible values are "EmailAddress" and "Domain". If this parameter is omitted, then all identities are listed.</p>
    pub fn set_identity_type(mut self, input: ::std::option::Option<crate::types::IdentityType>) -> Self {
        self.identity_type = input;
        self
    }
    /// <p>The type of the identities to list. Possible values are "EmailAddress" and "Domain". If this parameter is omitted, then all identities are listed.</p>
    pub fn get_identity_type(&self) -> &::std::option::Option<crate::types::IdentityType> {
        &self.identity_type
    }
    /// <p>The token to use for pagination.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use for pagination.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use for pagination.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of identities per page. Possible values are 1-1000 inclusive.</p>
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of identities per page. Possible values are 1-1000 inclusive.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>The maximum number of identities per page. Possible values are 1-1000 inclusive.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    /// Consumes the builder and constructs a [`ListIdentitiesInput`](crate::operation::list_identities::ListIdentitiesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_identities::ListIdentitiesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_identities::ListIdentitiesInput {
            identity_type: self.identity_type,
            next_token: self.next_token,
            max_items: self.max_items,
        })
    }
}
