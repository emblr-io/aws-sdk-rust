// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of all identities that you have attempted to verify under your Amazon Web Services account, regardless of verification status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListIdentitiesOutput {
    /// <p>A list of identities.</p>
    pub identities: ::std::vec::Vec<::std::string::String>,
    /// <p>The token used for pagination.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListIdentitiesOutput {
    /// <p>A list of identities.</p>
    pub fn identities(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.identities.deref()
    }
    /// <p>The token used for pagination.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListIdentitiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListIdentitiesOutput {
    /// Creates a new builder-style object to manufacture [`ListIdentitiesOutput`](crate::operation::list_identities::ListIdentitiesOutput).
    pub fn builder() -> crate::operation::list_identities::builders::ListIdentitiesOutputBuilder {
        crate::operation::list_identities::builders::ListIdentitiesOutputBuilder::default()
    }
}

/// A builder for [`ListIdentitiesOutput`](crate::operation::list_identities::ListIdentitiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListIdentitiesOutputBuilder {
    pub(crate) identities: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListIdentitiesOutputBuilder {
    /// Appends an item to `identities`.
    ///
    /// To override the contents of this collection use [`set_identities`](Self::set_identities).
    ///
    /// <p>A list of identities.</p>
    pub fn identities(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.identities.unwrap_or_default();
        v.push(input.into());
        self.identities = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of identities.</p>
    pub fn set_identities(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.identities = input;
        self
    }
    /// <p>A list of identities.</p>
    pub fn get_identities(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.identities
    }
    /// <p>The token used for pagination.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token used for pagination.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token used for pagination.</p>
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
    /// Consumes the builder and constructs a [`ListIdentitiesOutput`](crate::operation::list_identities::ListIdentitiesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`identities`](crate::operation::list_identities::builders::ListIdentitiesOutputBuilder::identities)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_identities::ListIdentitiesOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_identities::ListIdentitiesOutput {
            identities: self.identities.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "identities",
                    "identities was not specified but it is required when building ListIdentitiesOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
