// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListComponentBuildVersionsOutput {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The list of component summaries for the specified semantic version.</p>
    pub component_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::ComponentSummary>>,
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListComponentBuildVersionsOutput {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The list of component summaries for the specified semantic version.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.component_summary_list.is_none()`.
    pub fn component_summary_list(&self) -> &[crate::types::ComponentSummary] {
        self.component_summary_list.as_deref().unwrap_or_default()
    }
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListComponentBuildVersionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListComponentBuildVersionsOutput {
    /// Creates a new builder-style object to manufacture [`ListComponentBuildVersionsOutput`](crate::operation::list_component_build_versions::ListComponentBuildVersionsOutput).
    pub fn builder() -> crate::operation::list_component_build_versions::builders::ListComponentBuildVersionsOutputBuilder {
        crate::operation::list_component_build_versions::builders::ListComponentBuildVersionsOutputBuilder::default()
    }
}

/// A builder for [`ListComponentBuildVersionsOutput`](crate::operation::list_component_build_versions::ListComponentBuildVersionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListComponentBuildVersionsOutputBuilder {
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) component_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::ComponentSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListComponentBuildVersionsOutputBuilder {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// Appends an item to `component_summary_list`.
    ///
    /// To override the contents of this collection use [`set_component_summary_list`](Self::set_component_summary_list).
    ///
    /// <p>The list of component summaries for the specified semantic version.</p>
    pub fn component_summary_list(mut self, input: crate::types::ComponentSummary) -> Self {
        let mut v = self.component_summary_list.unwrap_or_default();
        v.push(input);
        self.component_summary_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of component summaries for the specified semantic version.</p>
    pub fn set_component_summary_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ComponentSummary>>) -> Self {
        self.component_summary_list = input;
        self
    }
    /// <p>The list of component summaries for the specified semantic version.</p>
    pub fn get_component_summary_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ComponentSummary>> {
        &self.component_summary_list
    }
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
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
    /// Consumes the builder and constructs a [`ListComponentBuildVersionsOutput`](crate::operation::list_component_build_versions::ListComponentBuildVersionsOutput).
    pub fn build(self) -> crate::operation::list_component_build_versions::ListComponentBuildVersionsOutput {
        crate::operation::list_component_build_versions::ListComponentBuildVersionsOutput {
            request_id: self.request_id,
            component_summary_list: self.component_summary_list,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
