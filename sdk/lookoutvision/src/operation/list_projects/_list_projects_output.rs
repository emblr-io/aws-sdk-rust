// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListProjectsOutput {
    /// <p>A list of projects in your AWS account.</p>
    pub projects: ::std::option::Option<::std::vec::Vec<crate::types::ProjectMetadata>>,
    /// <p>If the response is truncated, Amazon Lookout for Vision returns this token that you can use in the subsequent request to retrieve the next set of projects.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListProjectsOutput {
    /// <p>A list of projects in your AWS account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.projects.is_none()`.
    pub fn projects(&self) -> &[crate::types::ProjectMetadata] {
        self.projects.as_deref().unwrap_or_default()
    }
    /// <p>If the response is truncated, Amazon Lookout for Vision returns this token that you can use in the subsequent request to retrieve the next set of projects.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListProjectsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListProjectsOutput {
    /// Creates a new builder-style object to manufacture [`ListProjectsOutput`](crate::operation::list_projects::ListProjectsOutput).
    pub fn builder() -> crate::operation::list_projects::builders::ListProjectsOutputBuilder {
        crate::operation::list_projects::builders::ListProjectsOutputBuilder::default()
    }
}

/// A builder for [`ListProjectsOutput`](crate::operation::list_projects::ListProjectsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListProjectsOutputBuilder {
    pub(crate) projects: ::std::option::Option<::std::vec::Vec<crate::types::ProjectMetadata>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListProjectsOutputBuilder {
    /// Appends an item to `projects`.
    ///
    /// To override the contents of this collection use [`set_projects`](Self::set_projects).
    ///
    /// <p>A list of projects in your AWS account.</p>
    pub fn projects(mut self, input: crate::types::ProjectMetadata) -> Self {
        let mut v = self.projects.unwrap_or_default();
        v.push(input);
        self.projects = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of projects in your AWS account.</p>
    pub fn set_projects(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ProjectMetadata>>) -> Self {
        self.projects = input;
        self
    }
    /// <p>A list of projects in your AWS account.</p>
    pub fn get_projects(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ProjectMetadata>> {
        &self.projects
    }
    /// <p>If the response is truncated, Amazon Lookout for Vision returns this token that you can use in the subsequent request to retrieve the next set of projects.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response is truncated, Amazon Lookout for Vision returns this token that you can use in the subsequent request to retrieve the next set of projects.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response is truncated, Amazon Lookout for Vision returns this token that you can use in the subsequent request to retrieve the next set of projects.</p>
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
    /// Consumes the builder and constructs a [`ListProjectsOutput`](crate::operation::list_projects::ListProjectsOutput).
    pub fn build(self) -> crate::operation::list_projects::ListProjectsOutput {
        crate::operation::list_projects::ListProjectsOutput {
            projects: self.projects,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
