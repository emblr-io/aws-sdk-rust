// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPublicKeysOutput {
    /// <p>List of the matching public keys (summary information only).</p>
    pub public_keys: ::std::vec::Vec<crate::types::PublicKeySummary>,
    /// <p>If there are more public keys than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPublicKeysOutput {
    /// <p>List of the matching public keys (summary information only).</p>
    pub fn public_keys(&self) -> &[crate::types::PublicKeySummary] {
        use std::ops::Deref;
        self.public_keys.deref()
    }
    /// <p>If there are more public keys than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPublicKeysOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPublicKeysOutput {
    /// Creates a new builder-style object to manufacture [`ListPublicKeysOutput`](crate::operation::list_public_keys::ListPublicKeysOutput).
    pub fn builder() -> crate::operation::list_public_keys::builders::ListPublicKeysOutputBuilder {
        crate::operation::list_public_keys::builders::ListPublicKeysOutputBuilder::default()
    }
}

/// A builder for [`ListPublicKeysOutput`](crate::operation::list_public_keys::ListPublicKeysOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPublicKeysOutputBuilder {
    pub(crate) public_keys: ::std::option::Option<::std::vec::Vec<crate::types::PublicKeySummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPublicKeysOutputBuilder {
    /// Appends an item to `public_keys`.
    ///
    /// To override the contents of this collection use [`set_public_keys`](Self::set_public_keys).
    ///
    /// <p>List of the matching public keys (summary information only).</p>
    pub fn public_keys(mut self, input: crate::types::PublicKeySummary) -> Self {
        let mut v = self.public_keys.unwrap_or_default();
        v.push(input);
        self.public_keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of the matching public keys (summary information only).</p>
    pub fn set_public_keys(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PublicKeySummary>>) -> Self {
        self.public_keys = input;
        self
    }
    /// <p>List of the matching public keys (summary information only).</p>
    pub fn get_public_keys(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PublicKeySummary>> {
        &self.public_keys
    }
    /// <p>If there are more public keys than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are more public keys than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are more public keys than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
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
    /// Consumes the builder and constructs a [`ListPublicKeysOutput`](crate::operation::list_public_keys::ListPublicKeysOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`public_keys`](crate::operation::list_public_keys::builders::ListPublicKeysOutputBuilder::public_keys)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_public_keys::ListPublicKeysOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_public_keys::ListPublicKeysOutput {
            public_keys: self.public_keys.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "public_keys",
                    "public_keys was not specified but it is required when building ListPublicKeysOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
