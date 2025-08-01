// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchEntitiesOutput {
    /// <p>An array of descriptions for each entity returned in the search result.</p>
    pub descriptions: ::std::option::Option<::std::vec::Vec<crate::types::EntityDescription>>,
    /// <p>The string to specify as <code>nextToken</code> when you request the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SearchEntitiesOutput {
    /// <p>An array of descriptions for each entity returned in the search result.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.descriptions.is_none()`.
    pub fn descriptions(&self) -> &[crate::types::EntityDescription] {
        self.descriptions.as_deref().unwrap_or_default()
    }
    /// <p>The string to specify as <code>nextToken</code> when you request the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SearchEntitiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SearchEntitiesOutput {
    /// Creates a new builder-style object to manufacture [`SearchEntitiesOutput`](crate::operation::search_entities::SearchEntitiesOutput).
    pub fn builder() -> crate::operation::search_entities::builders::SearchEntitiesOutputBuilder {
        crate::operation::search_entities::builders::SearchEntitiesOutputBuilder::default()
    }
}

/// A builder for [`SearchEntitiesOutput`](crate::operation::search_entities::SearchEntitiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchEntitiesOutputBuilder {
    pub(crate) descriptions: ::std::option::Option<::std::vec::Vec<crate::types::EntityDescription>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SearchEntitiesOutputBuilder {
    /// Appends an item to `descriptions`.
    ///
    /// To override the contents of this collection use [`set_descriptions`](Self::set_descriptions).
    ///
    /// <p>An array of descriptions for each entity returned in the search result.</p>
    pub fn descriptions(mut self, input: crate::types::EntityDescription) -> Self {
        let mut v = self.descriptions.unwrap_or_default();
        v.push(input);
        self.descriptions = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of descriptions for each entity returned in the search result.</p>
    pub fn set_descriptions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EntityDescription>>) -> Self {
        self.descriptions = input;
        self
    }
    /// <p>An array of descriptions for each entity returned in the search result.</p>
    pub fn get_descriptions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EntityDescription>> {
        &self.descriptions
    }
    /// <p>The string to specify as <code>nextToken</code> when you request the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string to specify as <code>nextToken</code> when you request the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The string to specify as <code>nextToken</code> when you request the next page of results.</p>
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
    /// Consumes the builder and constructs a [`SearchEntitiesOutput`](crate::operation::search_entities::SearchEntitiesOutput).
    pub fn build(self) -> crate::operation::search_entities::SearchEntitiesOutput {
        crate::operation::search_entities::SearchEntitiesOutput {
            descriptions: self.descriptions,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
