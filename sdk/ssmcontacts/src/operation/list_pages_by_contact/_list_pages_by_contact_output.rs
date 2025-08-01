// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPagesByContactOutput {
    /// <p>The pagination token to continue to the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The list of engagements to a contact's contact channel.</p>
    pub pages: ::std::vec::Vec<crate::types::Page>,
    _request_id: Option<String>,
}
impl ListPagesByContactOutput {
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The list of engagements to a contact's contact channel.</p>
    pub fn pages(&self) -> &[crate::types::Page] {
        use std::ops::Deref;
        self.pages.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPagesByContactOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPagesByContactOutput {
    /// Creates a new builder-style object to manufacture [`ListPagesByContactOutput`](crate::operation::list_pages_by_contact::ListPagesByContactOutput).
    pub fn builder() -> crate::operation::list_pages_by_contact::builders::ListPagesByContactOutputBuilder {
        crate::operation::list_pages_by_contact::builders::ListPagesByContactOutputBuilder::default()
    }
}

/// A builder for [`ListPagesByContactOutput`](crate::operation::list_pages_by_contact::ListPagesByContactOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPagesByContactOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) pages: ::std::option::Option<::std::vec::Vec<crate::types::Page>>,
    _request_id: Option<String>,
}
impl ListPagesByContactOutputBuilder {
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `pages`.
    ///
    /// To override the contents of this collection use [`set_pages`](Self::set_pages).
    ///
    /// <p>The list of engagements to a contact's contact channel.</p>
    pub fn pages(mut self, input: crate::types::Page) -> Self {
        let mut v = self.pages.unwrap_or_default();
        v.push(input);
        self.pages = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of engagements to a contact's contact channel.</p>
    pub fn set_pages(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Page>>) -> Self {
        self.pages = input;
        self
    }
    /// <p>The list of engagements to a contact's contact channel.</p>
    pub fn get_pages(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Page>> {
        &self.pages
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListPagesByContactOutput`](crate::operation::list_pages_by_contact::ListPagesByContactOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`pages`](crate::operation::list_pages_by_contact::builders::ListPagesByContactOutputBuilder::pages)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_pages_by_contact::ListPagesByContactOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_pages_by_contact::ListPagesByContactOutput {
            next_token: self.next_token,
            pages: self.pages.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pages",
                    "pages was not specified but it is required when building ListPagesByContactOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
