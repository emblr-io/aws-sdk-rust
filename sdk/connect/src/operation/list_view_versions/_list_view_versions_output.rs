// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListViewVersionsOutput {
    /// <p>A list of view version summaries.</p>
    pub view_version_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::ViewVersionSummary>>,
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListViewVersionsOutput {
    /// <p>A list of view version summaries.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.view_version_summary_list.is_none()`.
    pub fn view_version_summary_list(&self) -> &[crate::types::ViewVersionSummary] {
        self.view_version_summary_list.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListViewVersionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListViewVersionsOutput {
    /// Creates a new builder-style object to manufacture [`ListViewVersionsOutput`](crate::operation::list_view_versions::ListViewVersionsOutput).
    pub fn builder() -> crate::operation::list_view_versions::builders::ListViewVersionsOutputBuilder {
        crate::operation::list_view_versions::builders::ListViewVersionsOutputBuilder::default()
    }
}

/// A builder for [`ListViewVersionsOutput`](crate::operation::list_view_versions::ListViewVersionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListViewVersionsOutputBuilder {
    pub(crate) view_version_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::ViewVersionSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListViewVersionsOutputBuilder {
    /// Appends an item to `view_version_summary_list`.
    ///
    /// To override the contents of this collection use [`set_view_version_summary_list`](Self::set_view_version_summary_list).
    ///
    /// <p>A list of view version summaries.</p>
    pub fn view_version_summary_list(mut self, input: crate::types::ViewVersionSummary) -> Self {
        let mut v = self.view_version_summary_list.unwrap_or_default();
        v.push(input);
        self.view_version_summary_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of view version summaries.</p>
    pub fn set_view_version_summary_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ViewVersionSummary>>) -> Self {
        self.view_version_summary_list = input;
        self
    }
    /// <p>A list of view version summaries.</p>
    pub fn get_view_version_summary_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ViewVersionSummary>> {
        &self.view_version_summary_list
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
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
    /// Consumes the builder and constructs a [`ListViewVersionsOutput`](crate::operation::list_view_versions::ListViewVersionsOutput).
    pub fn build(self) -> crate::operation::list_view_versions::ListViewVersionsOutput {
        crate::operation::list_view_versions::ListViewVersionsOutput {
            view_version_summary_list: self.view_version_summary_list,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
