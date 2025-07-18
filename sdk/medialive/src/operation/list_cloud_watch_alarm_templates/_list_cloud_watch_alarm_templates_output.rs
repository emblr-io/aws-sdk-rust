// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for ListCloudWatchAlarmTemplatesResponse
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCloudWatchAlarmTemplatesOutput {
    /// Placeholder documentation for __listOfCloudWatchAlarmTemplateSummary
    pub cloud_watch_alarm_templates: ::std::option::Option<::std::vec::Vec<crate::types::CloudWatchAlarmTemplateSummary>>,
    /// A token used to retrieve the next set of results in paginated list responses.
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListCloudWatchAlarmTemplatesOutput {
    /// Placeholder documentation for __listOfCloudWatchAlarmTemplateSummary
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cloud_watch_alarm_templates.is_none()`.
    pub fn cloud_watch_alarm_templates(&self) -> &[crate::types::CloudWatchAlarmTemplateSummary] {
        self.cloud_watch_alarm_templates.as_deref().unwrap_or_default()
    }
    /// A token used to retrieve the next set of results in paginated list responses.
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListCloudWatchAlarmTemplatesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListCloudWatchAlarmTemplatesOutput {
    /// Creates a new builder-style object to manufacture [`ListCloudWatchAlarmTemplatesOutput`](crate::operation::list_cloud_watch_alarm_templates::ListCloudWatchAlarmTemplatesOutput).
    pub fn builder() -> crate::operation::list_cloud_watch_alarm_templates::builders::ListCloudWatchAlarmTemplatesOutputBuilder {
        crate::operation::list_cloud_watch_alarm_templates::builders::ListCloudWatchAlarmTemplatesOutputBuilder::default()
    }
}

/// A builder for [`ListCloudWatchAlarmTemplatesOutput`](crate::operation::list_cloud_watch_alarm_templates::ListCloudWatchAlarmTemplatesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCloudWatchAlarmTemplatesOutputBuilder {
    pub(crate) cloud_watch_alarm_templates: ::std::option::Option<::std::vec::Vec<crate::types::CloudWatchAlarmTemplateSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListCloudWatchAlarmTemplatesOutputBuilder {
    /// Appends an item to `cloud_watch_alarm_templates`.
    ///
    /// To override the contents of this collection use [`set_cloud_watch_alarm_templates`](Self::set_cloud_watch_alarm_templates).
    ///
    /// Placeholder documentation for __listOfCloudWatchAlarmTemplateSummary
    pub fn cloud_watch_alarm_templates(mut self, input: crate::types::CloudWatchAlarmTemplateSummary) -> Self {
        let mut v = self.cloud_watch_alarm_templates.unwrap_or_default();
        v.push(input);
        self.cloud_watch_alarm_templates = ::std::option::Option::Some(v);
        self
    }
    /// Placeholder documentation for __listOfCloudWatchAlarmTemplateSummary
    pub fn set_cloud_watch_alarm_templates(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::CloudWatchAlarmTemplateSummary>>,
    ) -> Self {
        self.cloud_watch_alarm_templates = input;
        self
    }
    /// Placeholder documentation for __listOfCloudWatchAlarmTemplateSummary
    pub fn get_cloud_watch_alarm_templates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CloudWatchAlarmTemplateSummary>> {
        &self.cloud_watch_alarm_templates
    }
    /// A token used to retrieve the next set of results in paginated list responses.
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// A token used to retrieve the next set of results in paginated list responses.
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// A token used to retrieve the next set of results in paginated list responses.
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
    /// Consumes the builder and constructs a [`ListCloudWatchAlarmTemplatesOutput`](crate::operation::list_cloud_watch_alarm_templates::ListCloudWatchAlarmTemplatesOutput).
    pub fn build(self) -> crate::operation::list_cloud_watch_alarm_templates::ListCloudWatchAlarmTemplatesOutput {
        crate::operation::list_cloud_watch_alarm_templates::ListCloudWatchAlarmTemplatesOutput {
            cloud_watch_alarm_templates: self.cloud_watch_alarm_templates,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
