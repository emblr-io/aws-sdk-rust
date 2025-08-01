// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCustomActionsOutput {
    /// <p>A list of custom actions.</p>
    pub custom_actions: ::std::vec::Vec<::std::string::String>,
    /// <p>An optional token returned from a prior request. Use this token for pagination of results from this action. If this parameter is specified, the response includes only results beyond the token, up to the value specified by MaxResults.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListCustomActionsOutput {
    /// <p>A list of custom actions.</p>
    pub fn custom_actions(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.custom_actions.deref()
    }
    /// <p>An optional token returned from a prior request. Use this token for pagination of results from this action. If this parameter is specified, the response includes only results beyond the token, up to the value specified by MaxResults.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListCustomActionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListCustomActionsOutput {
    /// Creates a new builder-style object to manufacture [`ListCustomActionsOutput`](crate::operation::list_custom_actions::ListCustomActionsOutput).
    pub fn builder() -> crate::operation::list_custom_actions::builders::ListCustomActionsOutputBuilder {
        crate::operation::list_custom_actions::builders::ListCustomActionsOutputBuilder::default()
    }
}

/// A builder for [`ListCustomActionsOutput`](crate::operation::list_custom_actions::ListCustomActionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCustomActionsOutputBuilder {
    pub(crate) custom_actions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListCustomActionsOutputBuilder {
    /// Appends an item to `custom_actions`.
    ///
    /// To override the contents of this collection use [`set_custom_actions`](Self::set_custom_actions).
    ///
    /// <p>A list of custom actions.</p>
    pub fn custom_actions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.custom_actions.unwrap_or_default();
        v.push(input.into());
        self.custom_actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of custom actions.</p>
    pub fn set_custom_actions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.custom_actions = input;
        self
    }
    /// <p>A list of custom actions.</p>
    pub fn get_custom_actions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.custom_actions
    }
    /// <p>An optional token returned from a prior request. Use this token for pagination of results from this action. If this parameter is specified, the response includes only results beyond the token, up to the value specified by MaxResults.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional token returned from a prior request. Use this token for pagination of results from this action. If this parameter is specified, the response includes only results beyond the token, up to the value specified by MaxResults.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An optional token returned from a prior request. Use this token for pagination of results from this action. If this parameter is specified, the response includes only results beyond the token, up to the value specified by MaxResults.</p>
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
    /// Consumes the builder and constructs a [`ListCustomActionsOutput`](crate::operation::list_custom_actions::ListCustomActionsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`custom_actions`](crate::operation::list_custom_actions::builders::ListCustomActionsOutputBuilder::custom_actions)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_custom_actions::ListCustomActionsOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_custom_actions::ListCustomActionsOutput {
            custom_actions: self.custom_actions.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "custom_actions",
                    "custom_actions was not specified but it is required when building ListCustomActionsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
