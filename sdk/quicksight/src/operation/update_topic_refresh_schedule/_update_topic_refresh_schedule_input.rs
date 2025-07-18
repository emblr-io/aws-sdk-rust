// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTopicRefreshScheduleInput {
    /// <p>The ID of the Amazon Web Services account that contains the topic whose refresh schedule you want to update.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the topic that you want to modify. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub topic_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the dataset.</p>
    pub dataset_id: ::std::option::Option<::std::string::String>,
    /// <p>The definition of a refresh schedule.</p>
    pub refresh_schedule: ::std::option::Option<crate::types::TopicRefreshSchedule>,
}
impl UpdateTopicRefreshScheduleInput {
    /// <p>The ID of the Amazon Web Services account that contains the topic whose refresh schedule you want to update.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID of the topic that you want to modify. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn topic_id(&self) -> ::std::option::Option<&str> {
        self.topic_id.as_deref()
    }
    /// <p>The ID of the dataset.</p>
    pub fn dataset_id(&self) -> ::std::option::Option<&str> {
        self.dataset_id.as_deref()
    }
    /// <p>The definition of a refresh schedule.</p>
    pub fn refresh_schedule(&self) -> ::std::option::Option<&crate::types::TopicRefreshSchedule> {
        self.refresh_schedule.as_ref()
    }
}
impl UpdateTopicRefreshScheduleInput {
    /// Creates a new builder-style object to manufacture [`UpdateTopicRefreshScheduleInput`](crate::operation::update_topic_refresh_schedule::UpdateTopicRefreshScheduleInput).
    pub fn builder() -> crate::operation::update_topic_refresh_schedule::builders::UpdateTopicRefreshScheduleInputBuilder {
        crate::operation::update_topic_refresh_schedule::builders::UpdateTopicRefreshScheduleInputBuilder::default()
    }
}

/// A builder for [`UpdateTopicRefreshScheduleInput`](crate::operation::update_topic_refresh_schedule::UpdateTopicRefreshScheduleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTopicRefreshScheduleInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) topic_id: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_id: ::std::option::Option<::std::string::String>,
    pub(crate) refresh_schedule: ::std::option::Option<crate::types::TopicRefreshSchedule>,
}
impl UpdateTopicRefreshScheduleInputBuilder {
    /// <p>The ID of the Amazon Web Services account that contains the topic whose refresh schedule you want to update.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the topic whose refresh schedule you want to update.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the topic whose refresh schedule you want to update.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID of the topic that you want to modify. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    /// This field is required.
    pub fn topic_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the topic that you want to modify. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn set_topic_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_id = input;
        self
    }
    /// <p>The ID of the topic that you want to modify. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn get_topic_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_id
    }
    /// <p>The ID of the dataset.</p>
    /// This field is required.
    pub fn dataset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the dataset.</p>
    pub fn set_dataset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_id = input;
        self
    }
    /// <p>The ID of the dataset.</p>
    pub fn get_dataset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_id
    }
    /// <p>The definition of a refresh schedule.</p>
    /// This field is required.
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
    /// Consumes the builder and constructs a [`UpdateTopicRefreshScheduleInput`](crate::operation::update_topic_refresh_schedule::UpdateTopicRefreshScheduleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_topic_refresh_schedule::UpdateTopicRefreshScheduleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_topic_refresh_schedule::UpdateTopicRefreshScheduleInput {
            aws_account_id: self.aws_account_id,
            topic_id: self.topic_id,
            dataset_id: self.dataset_id,
            refresh_schedule: self.refresh_schedule,
        })
    }
}
