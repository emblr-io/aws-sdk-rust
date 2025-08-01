// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAppsOutput {
    /// <p>The application summaries.</p>
    pub apps: ::std::option::Option<::std::vec::Vec<crate::types::AppSummary>>,
    /// <p>The token required to retrieve the next set of results. This value is null when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAppsOutput {
    /// <p>The application summaries.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.apps.is_none()`.
    pub fn apps(&self) -> &[crate::types::AppSummary] {
        self.apps.as_deref().unwrap_or_default()
    }
    /// <p>The token required to retrieve the next set of results. This value is null when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListAppsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAppsOutput {
    /// Creates a new builder-style object to manufacture [`ListAppsOutput`](crate::operation::list_apps::ListAppsOutput).
    pub fn builder() -> crate::operation::list_apps::builders::ListAppsOutputBuilder {
        crate::operation::list_apps::builders::ListAppsOutputBuilder::default()
    }
}

/// A builder for [`ListAppsOutput`](crate::operation::list_apps::ListAppsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAppsOutputBuilder {
    pub(crate) apps: ::std::option::Option<::std::vec::Vec<crate::types::AppSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAppsOutputBuilder {
    /// Appends an item to `apps`.
    ///
    /// To override the contents of this collection use [`set_apps`](Self::set_apps).
    ///
    /// <p>The application summaries.</p>
    pub fn apps(mut self, input: crate::types::AppSummary) -> Self {
        let mut v = self.apps.unwrap_or_default();
        v.push(input);
        self.apps = ::std::option::Option::Some(v);
        self
    }
    /// <p>The application summaries.</p>
    pub fn set_apps(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AppSummary>>) -> Self {
        self.apps = input;
        self
    }
    /// <p>The application summaries.</p>
    pub fn get_apps(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AppSummary>> {
        &self.apps
    }
    /// <p>The token required to retrieve the next set of results. This value is null when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token required to retrieve the next set of results. This value is null when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token required to retrieve the next set of results. This value is null when there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`ListAppsOutput`](crate::operation::list_apps::ListAppsOutput).
    pub fn build(self) -> crate::operation::list_apps::ListAppsOutput {
        crate::operation::list_apps::ListAppsOutput {
            apps: self.apps,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
