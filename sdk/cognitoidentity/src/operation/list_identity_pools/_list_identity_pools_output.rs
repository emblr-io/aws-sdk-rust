// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a successful ListIdentityPools action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListIdentityPoolsOutput {
    /// <p>The identity pools returned by the ListIdentityPools action.</p>
    pub identity_pools: ::std::option::Option<::std::vec::Vec<crate::types::IdentityPoolShortDescription>>,
    /// <p>A pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListIdentityPoolsOutput {
    /// <p>The identity pools returned by the ListIdentityPools action.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.identity_pools.is_none()`.
    pub fn identity_pools(&self) -> &[crate::types::IdentityPoolShortDescription] {
        self.identity_pools.as_deref().unwrap_or_default()
    }
    /// <p>A pagination token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListIdentityPoolsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListIdentityPoolsOutput {
    /// Creates a new builder-style object to manufacture [`ListIdentityPoolsOutput`](crate::operation::list_identity_pools::ListIdentityPoolsOutput).
    pub fn builder() -> crate::operation::list_identity_pools::builders::ListIdentityPoolsOutputBuilder {
        crate::operation::list_identity_pools::builders::ListIdentityPoolsOutputBuilder::default()
    }
}

/// A builder for [`ListIdentityPoolsOutput`](crate::operation::list_identity_pools::ListIdentityPoolsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListIdentityPoolsOutputBuilder {
    pub(crate) identity_pools: ::std::option::Option<::std::vec::Vec<crate::types::IdentityPoolShortDescription>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListIdentityPoolsOutputBuilder {
    /// Appends an item to `identity_pools`.
    ///
    /// To override the contents of this collection use [`set_identity_pools`](Self::set_identity_pools).
    ///
    /// <p>The identity pools returned by the ListIdentityPools action.</p>
    pub fn identity_pools(mut self, input: crate::types::IdentityPoolShortDescription) -> Self {
        let mut v = self.identity_pools.unwrap_or_default();
        v.push(input);
        self.identity_pools = ::std::option::Option::Some(v);
        self
    }
    /// <p>The identity pools returned by the ListIdentityPools action.</p>
    pub fn set_identity_pools(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IdentityPoolShortDescription>>) -> Self {
        self.identity_pools = input;
        self
    }
    /// <p>The identity pools returned by the ListIdentityPools action.</p>
    pub fn get_identity_pools(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IdentityPoolShortDescription>> {
        &self.identity_pools
    }
    /// <p>A pagination token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListIdentityPoolsOutput`](crate::operation::list_identity_pools::ListIdentityPoolsOutput).
    pub fn build(self) -> crate::operation::list_identity_pools::ListIdentityPoolsOutput {
        crate::operation::list_identity_pools::ListIdentityPoolsOutput {
            identity_pools: self.identity_pools,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
