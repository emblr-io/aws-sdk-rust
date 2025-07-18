// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchRelatedItemsOutput {
    /// <p>The token for the next set of results. This is null if there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of items related to a case.</p>
    pub related_items: ::std::vec::Vec<::std::option::Option<crate::types::SearchRelatedItemsResponseItem>>,
    _request_id: Option<String>,
}
impl SearchRelatedItemsOutput {
    /// <p>The token for the next set of results. This is null if there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of items related to a case.</p>
    pub fn related_items(&self) -> &[::std::option::Option<crate::types::SearchRelatedItemsResponseItem>] {
        use std::ops::Deref;
        self.related_items.deref()
    }
}
impl ::aws_types::request_id::RequestId for SearchRelatedItemsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SearchRelatedItemsOutput {
    /// Creates a new builder-style object to manufacture [`SearchRelatedItemsOutput`](crate::operation::search_related_items::SearchRelatedItemsOutput).
    pub fn builder() -> crate::operation::search_related_items::builders::SearchRelatedItemsOutputBuilder {
        crate::operation::search_related_items::builders::SearchRelatedItemsOutputBuilder::default()
    }
}

/// A builder for [`SearchRelatedItemsOutput`](crate::operation::search_related_items::SearchRelatedItemsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchRelatedItemsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) related_items: ::std::option::Option<::std::vec::Vec<::std::option::Option<crate::types::SearchRelatedItemsResponseItem>>>,
    _request_id: Option<String>,
}
impl SearchRelatedItemsOutputBuilder {
    /// <p>The token for the next set of results. This is null if there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. This is null if there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. This is null if there are no more results to return.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `related_items`.
    ///
    /// To override the contents of this collection use [`set_related_items`](Self::set_related_items).
    ///
    /// <p>A list of items related to a case.</p>
    pub fn related_items(mut self, input: ::std::option::Option<crate::types::SearchRelatedItemsResponseItem>) -> Self {
        let mut v = self.related_items.unwrap_or_default();
        v.push(input);
        self.related_items = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of items related to a case.</p>
    pub fn set_related_items(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<::std::option::Option<crate::types::SearchRelatedItemsResponseItem>>>,
    ) -> Self {
        self.related_items = input;
        self
    }
    /// <p>A list of items related to a case.</p>
    pub fn get_related_items(&self) -> &::std::option::Option<::std::vec::Vec<::std::option::Option<crate::types::SearchRelatedItemsResponseItem>>> {
        &self.related_items
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SearchRelatedItemsOutput`](crate::operation::search_related_items::SearchRelatedItemsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`related_items`](crate::operation::search_related_items::builders::SearchRelatedItemsOutputBuilder::related_items)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::search_related_items::SearchRelatedItemsOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::search_related_items::SearchRelatedItemsOutput {
            next_token: self.next_token,
            related_items: self.related_items.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "related_items",
                    "related_items was not specified but it is required when building SearchRelatedItemsOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
