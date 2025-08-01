// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListBuildsForProjectOutput {
    /// <p>A list of build identifiers for the specified build project, with each build ID representing a single build.</p>
    pub ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>If there are more than 100 items in the list, only the first 100 items are returned, along with a unique string called a <i>nextToken</i>. To get the next batch of items in the list, call this operation again, adding the next token to the call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListBuildsForProjectOutput {
    /// <p>A list of build identifiers for the specified build project, with each build ID representing a single build.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ids.is_none()`.
    pub fn ids(&self) -> &[::std::string::String] {
        self.ids.as_deref().unwrap_or_default()
    }
    /// <p>If there are more than 100 items in the list, only the first 100 items are returned, along with a unique string called a <i>nextToken</i>. To get the next batch of items in the list, call this operation again, adding the next token to the call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListBuildsForProjectOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListBuildsForProjectOutput {
    /// Creates a new builder-style object to manufacture [`ListBuildsForProjectOutput`](crate::operation::list_builds_for_project::ListBuildsForProjectOutput).
    pub fn builder() -> crate::operation::list_builds_for_project::builders::ListBuildsForProjectOutputBuilder {
        crate::operation::list_builds_for_project::builders::ListBuildsForProjectOutputBuilder::default()
    }
}

/// A builder for [`ListBuildsForProjectOutput`](crate::operation::list_builds_for_project::ListBuildsForProjectOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListBuildsForProjectOutputBuilder {
    pub(crate) ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListBuildsForProjectOutputBuilder {
    /// Appends an item to `ids`.
    ///
    /// To override the contents of this collection use [`set_ids`](Self::set_ids).
    ///
    /// <p>A list of build identifiers for the specified build project, with each build ID representing a single build.</p>
    pub fn ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ids.unwrap_or_default();
        v.push(input.into());
        self.ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of build identifiers for the specified build project, with each build ID representing a single build.</p>
    pub fn set_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ids = input;
        self
    }
    /// <p>A list of build identifiers for the specified build project, with each build ID representing a single build.</p>
    pub fn get_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ids
    }
    /// <p>If there are more than 100 items in the list, only the first 100 items are returned, along with a unique string called a <i>nextToken</i>. To get the next batch of items in the list, call this operation again, adding the next token to the call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are more than 100 items in the list, only the first 100 items are returned, along with a unique string called a <i>nextToken</i>. To get the next batch of items in the list, call this operation again, adding the next token to the call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are more than 100 items in the list, only the first 100 items are returned, along with a unique string called a <i>nextToken</i>. To get the next batch of items in the list, call this operation again, adding the next token to the call.</p>
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
    /// Consumes the builder and constructs a [`ListBuildsForProjectOutput`](crate::operation::list_builds_for_project::ListBuildsForProjectOutput).
    pub fn build(self) -> crate::operation::list_builds_for_project::ListBuildsForProjectOutput {
        crate::operation::list_builds_for_project::ListBuildsForProjectOutput {
            ids: self.ids,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
