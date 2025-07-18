// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListKeysOutput {
    /// <p>The list of keys created within the caller's Amazon Web Services account and Amazon Web Services Region.</p>
    pub keys: ::std::vec::Vec<crate::types::KeySummary>,
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListKeysOutput {
    /// <p>The list of keys created within the caller's Amazon Web Services account and Amazon Web Services Region.</p>
    pub fn keys(&self) -> &[crate::types::KeySummary] {
        use std::ops::Deref;
        self.keys.deref()
    }
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListKeysOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListKeysOutput {
    /// Creates a new builder-style object to manufacture [`ListKeysOutput`](crate::operation::list_keys::ListKeysOutput).
    pub fn builder() -> crate::operation::list_keys::builders::ListKeysOutputBuilder {
        crate::operation::list_keys::builders::ListKeysOutputBuilder::default()
    }
}

/// A builder for [`ListKeysOutput`](crate::operation::list_keys::ListKeysOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListKeysOutputBuilder {
    pub(crate) keys: ::std::option::Option<::std::vec::Vec<crate::types::KeySummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListKeysOutputBuilder {
    /// Appends an item to `keys`.
    ///
    /// To override the contents of this collection use [`set_keys`](Self::set_keys).
    ///
    /// <p>The list of keys created within the caller's Amazon Web Services account and Amazon Web Services Region.</p>
    pub fn keys(mut self, input: crate::types::KeySummary) -> Self {
        let mut v = self.keys.unwrap_or_default();
        v.push(input);
        self.keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of keys created within the caller's Amazon Web Services account and Amazon Web Services Region.</p>
    pub fn set_keys(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::KeySummary>>) -> Self {
        self.keys = input;
        self
    }
    /// <p>The list of keys created within the caller's Amazon Web Services account and Amazon Web Services Region.</p>
    pub fn get_keys(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::KeySummary>> {
        &self.keys
    }
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
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
    /// Consumes the builder and constructs a [`ListKeysOutput`](crate::operation::list_keys::ListKeysOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`keys`](crate::operation::list_keys::builders::ListKeysOutputBuilder::keys)
    pub fn build(self) -> ::std::result::Result<crate::operation::list_keys::ListKeysOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_keys::ListKeysOutput {
            keys: self.keys.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "keys",
                    "keys was not specified but it is required when building ListKeysOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
