// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAppOutput {
    /// <p>Information about the application.</p>
    pub app_summary: ::std::option::Option<crate::types::AppSummary>,
    /// <p>The server groups that belong to the application.</p>
    pub server_groups: ::std::option::Option<::std::vec::Vec<crate::types::ServerGroup>>,
    /// <p>The tags associated with the application.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    _request_id: Option<String>,
}
impl GetAppOutput {
    /// <p>Information about the application.</p>
    pub fn app_summary(&self) -> ::std::option::Option<&crate::types::AppSummary> {
        self.app_summary.as_ref()
    }
    /// <p>The server groups that belong to the application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.server_groups.is_none()`.
    pub fn server_groups(&self) -> &[crate::types::ServerGroup] {
        self.server_groups.as_deref().unwrap_or_default()
    }
    /// <p>The tags associated with the application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetAppOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAppOutput {
    /// Creates a new builder-style object to manufacture [`GetAppOutput`](crate::operation::get_app::GetAppOutput).
    pub fn builder() -> crate::operation::get_app::builders::GetAppOutputBuilder {
        crate::operation::get_app::builders::GetAppOutputBuilder::default()
    }
}

/// A builder for [`GetAppOutput`](crate::operation::get_app::GetAppOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAppOutputBuilder {
    pub(crate) app_summary: ::std::option::Option<crate::types::AppSummary>,
    pub(crate) server_groups: ::std::option::Option<::std::vec::Vec<crate::types::ServerGroup>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    _request_id: Option<String>,
}
impl GetAppOutputBuilder {
    /// <p>Information about the application.</p>
    pub fn app_summary(mut self, input: crate::types::AppSummary) -> Self {
        self.app_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the application.</p>
    pub fn set_app_summary(mut self, input: ::std::option::Option<crate::types::AppSummary>) -> Self {
        self.app_summary = input;
        self
    }
    /// <p>Information about the application.</p>
    pub fn get_app_summary(&self) -> &::std::option::Option<crate::types::AppSummary> {
        &self.app_summary
    }
    /// Appends an item to `server_groups`.
    ///
    /// To override the contents of this collection use [`set_server_groups`](Self::set_server_groups).
    ///
    /// <p>The server groups that belong to the application.</p>
    pub fn server_groups(mut self, input: crate::types::ServerGroup) -> Self {
        let mut v = self.server_groups.unwrap_or_default();
        v.push(input);
        self.server_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The server groups that belong to the application.</p>
    pub fn set_server_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServerGroup>>) -> Self {
        self.server_groups = input;
        self
    }
    /// <p>The server groups that belong to the application.</p>
    pub fn get_server_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServerGroup>> {
        &self.server_groups
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags associated with the application.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags associated with the application.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags associated with the application.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAppOutput`](crate::operation::get_app::GetAppOutput).
    pub fn build(self) -> crate::operation::get_app::GetAppOutput {
        crate::operation::get_app::GetAppOutput {
            app_summary: self.app_summary,
            server_groups: self.server_groups,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
