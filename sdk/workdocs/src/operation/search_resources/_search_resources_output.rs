// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchResourcesOutput {
    /// <p>List of Documents, Folders, Comments, and Document Versions matching the query.</p>
    pub items: ::std::option::Option<::std::vec::Vec<crate::types::ResponseItem>>,
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SearchResourcesOutput {
    /// <p>List of Documents, Folders, Comments, and Document Versions matching the query.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[crate::types::ResponseItem] {
        self.items.as_deref().unwrap_or_default()
    }
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SearchResourcesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SearchResourcesOutput {
    /// Creates a new builder-style object to manufacture [`SearchResourcesOutput`](crate::operation::search_resources::SearchResourcesOutput).
    pub fn builder() -> crate::operation::search_resources::builders::SearchResourcesOutputBuilder {
        crate::operation::search_resources::builders::SearchResourcesOutputBuilder::default()
    }
}

/// A builder for [`SearchResourcesOutput`](crate::operation::search_resources::SearchResourcesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchResourcesOutputBuilder {
    pub(crate) items: ::std::option::Option<::std::vec::Vec<crate::types::ResponseItem>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SearchResourcesOutputBuilder {
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>List of Documents, Folders, Comments, and Document Versions matching the query.</p>
    pub fn items(mut self, input: crate::types::ResponseItem) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of Documents, Folders, Comments, and Document Versions matching the query.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResponseItem>>) -> Self {
        self.items = input;
        self
    }
    /// <p>List of Documents, Folders, Comments, and Document Versions matching the query.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResponseItem>> {
        &self.items
    }
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SearchResourcesOutput`](crate::operation::search_resources::SearchResourcesOutput).
    pub fn build(self) -> crate::operation::search_resources::SearchResourcesOutput {
        crate::operation::search_resources::SearchResourcesOutput {
            items: self.items,
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
