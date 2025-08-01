// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTopicRefreshScheduleOutput {
    /// <p>The ID of the topic that contains the refresh schedule that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub topic_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub topic_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub dataset_arn: ::std::option::Option<::std::string::String>,
    /// <p>The definition of a refresh schedule.</p>
    pub refresh_schedule: ::std::option::Option<crate::types::TopicRefreshSchedule>,
    /// <p>The HTTP status of the request.</p>
    pub status: i32,
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeTopicRefreshScheduleOutput {
    /// <p>The ID of the topic that contains the refresh schedule that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn topic_id(&self) -> ::std::option::Option<&str> {
        self.topic_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub fn topic_arn(&self) -> ::std::option::Option<&str> {
        self.topic_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub fn dataset_arn(&self) -> ::std::option::Option<&str> {
        self.dataset_arn.as_deref()
    }
    /// <p>The definition of a refresh schedule.</p>
    pub fn refresh_schedule(&self) -> ::std::option::Option<&crate::types::TopicRefreshSchedule> {
        self.refresh_schedule.as_ref()
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
impl ::aws_types::request_id::RequestId for DescribeTopicRefreshScheduleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeTopicRefreshScheduleOutput {
    /// Creates a new builder-style object to manufacture [`DescribeTopicRefreshScheduleOutput`](crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleOutput).
    pub fn builder() -> crate::operation::describe_topic_refresh_schedule::builders::DescribeTopicRefreshScheduleOutputBuilder {
        crate::operation::describe_topic_refresh_schedule::builders::DescribeTopicRefreshScheduleOutputBuilder::default()
    }
}

/// A builder for [`DescribeTopicRefreshScheduleOutput`](crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTopicRefreshScheduleOutputBuilder {
    pub(crate) topic_id: ::std::option::Option<::std::string::String>,
    pub(crate) topic_arn: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_arn: ::std::option::Option<::std::string::String>,
    pub(crate) refresh_schedule: ::std::option::Option<crate::types::TopicRefreshSchedule>,
    pub(crate) status: ::std::option::Option<i32>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeTopicRefreshScheduleOutputBuilder {
    /// <p>The ID of the topic that contains the refresh schedule that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn topic_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the topic that contains the refresh schedule that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn set_topic_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_id = input;
        self
    }
    /// <p>The ID of the topic that contains the refresh schedule that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
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
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub fn dataset_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub fn set_dataset_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub fn get_dataset_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_arn
    }
    /// <p>The definition of a refresh schedule.</p>
    pub fn refresh_schedule(mut self, input: crate::types::TopicRefreshSchedule) -> Self {
        self.refresh_schedule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The definition of a refresh schedule.</p>
    pub fn set_refresh_schedule(mut self, input: ::std::option::Option<crate::types::TopicRefreshSchedule>) -> Self {
        self.refresh_schedule = input;
        self
    }
    /// <p>The definition of a refresh schedule.</p>
    pub fn get_refresh_schedule(&self) -> &::std::option::Option<crate::types::TopicRefreshSchedule> {
        &self.refresh_schedule
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
    /// Consumes the builder and constructs a [`DescribeTopicRefreshScheduleOutput`](crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleOutput).
    pub fn build(self) -> crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleOutput {
        crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleOutput {
            topic_id: self.topic_id,
            topic_arn: self.topic_arn,
            dataset_arn: self.dataset_arn,
            refresh_schedule: self.refresh_schedule,
            status: self.status.unwrap_or_default(),
            request_id: self.request_id,
            _request_id: self._request_id,
        }
    }
}
