// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTopicRefreshSchedulesOutput {
    /// <p>The ID for the topic that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub topic_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub topic_arn: ::std::option::Option<::std::string::String>,
    /// <p>The list of topic refresh schedules.</p>
    pub refresh_schedules: ::std::option::Option<::std::vec::Vec<crate::types::TopicRefreshScheduleSummary>>,
    /// <p>The HTTP status of the request.</p>
    pub status: i32,
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListTopicRefreshSchedulesOutput {
    /// <p>The ID for the topic that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn topic_id(&self) -> ::std::option::Option<&str> {
        self.topic_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub fn topic_arn(&self) -> ::std::option::Option<&str> {
        self.topic_arn.as_deref()
    }
    /// <p>The list of topic refresh schedules.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.refresh_schedules.is_none()`.
    pub fn refresh_schedules(&self) -> &[crate::types::TopicRefreshScheduleSummary] {
        self.refresh_schedules.as_deref().unwrap_or_default()
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(&self) -> i32 {
        self.status
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListTopicRefreshSchedulesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListTopicRefreshSchedulesOutput {
    /// Creates a new builder-style object to manufacture [`ListTopicRefreshSchedulesOutput`](crate::operation::list_topic_refresh_schedules::ListTopicRefreshSchedulesOutput).
    pub fn builder() -> crate::operation::list_topic_refresh_schedules::builders::ListTopicRefreshSchedulesOutputBuilder {
        crate::operation::list_topic_refresh_schedules::builders::ListTopicRefreshSchedulesOutputBuilder::default()
    }
}

/// A builder for [`ListTopicRefreshSchedulesOutput`](crate::operation::list_topic_refresh_schedules::ListTopicRefreshSchedulesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTopicRefreshSchedulesOutputBuilder {
    pub(crate) topic_id: ::std::option::Option<::std::string::String>,
    pub(crate) topic_arn: ::std::option::Option<::std::string::String>,
    pub(crate) refresh_schedules: ::std::option::Option<::std::vec::Vec<crate::types::TopicRefreshScheduleSummary>>,
    pub(crate) status: ::std::option::Option<i32>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListTopicRefreshSchedulesOutputBuilder {
    /// <p>The ID for the topic that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn topic_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the topic that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn set_topic_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_id = input;
        self
    }
    /// <p>The ID for the topic that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn get_topic_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_id
    }
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub fn topic_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub fn set_topic_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub fn get_topic_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_arn
    }
    /// Appends an item to `refresh_schedules`.
    ///
    /// To override the contents of this collection use [`set_refresh_schedules`](Self::set_refresh_schedules).
    ///
    /// <p>The list of topic refresh schedules.</p>
    pub fn refresh_schedules(mut self, input: crate::types::TopicRefreshScheduleSummary) -> Self {
        let mut v = self.refresh_schedules.unwrap_or_default();
        v.push(input);
        self.refresh_schedules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of topic refresh schedules.</p>
    pub fn set_refresh_schedules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TopicRefreshScheduleSummary>>) -> Self {
        self.refresh_schedules = input;
        self
    }
    /// <p>The list of topic refresh schedules.</p>
    pub fn get_refresh_schedules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TopicRefreshScheduleSummary>> {
        &self.refresh_schedules
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(mut self, input: i32) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<i32>) -> Self {
        self.status = input;
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn get_status(&self) -> &::std::option::Option<i32> {
        &self.status
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListTopicRefreshSchedulesOutput`](crate::operation::list_topic_refresh_schedules::ListTopicRefreshSchedulesOutput).
    pub fn build(self) -> crate::operation::list_topic_refresh_schedules::ListTopicRefreshSchedulesOutput {
        crate::operation::list_topic_refresh_schedules::ListTopicRefreshSchedulesOutput {
            topic_id: self.topic_id,
            topic_arn: self.topic_arn,
            refresh_schedules: self.refresh_schedules,
            status: self.status.unwrap_or_default(),
            request_id: self.request_id,
            _request_id: self._request_id,
        }
    }
}
