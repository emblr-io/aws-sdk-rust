// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTopicRefreshScheduleInput {
    /// <p>The Amazon Web Services account ID.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the topic that contains the refresh schedule that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub topic_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the dataset.</p>
    pub dataset_id: ::std::option::Option<::std::string::String>,
}
impl DescribeTopicRefreshScheduleInput {
    /// <p>The Amazon Web Services account ID.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID of the topic that contains the refresh schedule that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn topic_id(&self) -> ::std::option::Option<&str> {
        self.topic_id.as_deref()
    }
    /// <p>The ID of the dataset.</p>
    pub fn dataset_id(&self) -> ::std::option::Option<&str> {
        self.dataset_id.as_deref()
    }
}
impl DescribeTopicRefreshScheduleInput {
    /// Creates a new builder-style object to manufacture [`DescribeTopicRefreshScheduleInput`](crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleInput).
    pub fn builder() -> crate::operation::describe_topic_refresh_schedule::builders::DescribeTopicRefreshScheduleInputBuilder {
        crate::operation::describe_topic_refresh_schedule::builders::DescribeTopicRefreshScheduleInputBuilder::default()
    }
}

/// A builder for [`DescribeTopicRefreshScheduleInput`](crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTopicRefreshScheduleInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) topic_id: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_id: ::std::option::Option<::std::string::String>,
}
impl DescribeTopicRefreshScheduleInputBuilder {
    /// <p>The Amazon Web Services account ID.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID of the topic that contains the refresh schedule that you want to describe. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    /// This field is required.
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
    /// Consumes the builder and constructs a [`DescribeTopicRefreshScheduleInput`](crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_topic_refresh_schedule::DescribeTopicRefreshScheduleInput {
            aws_account_id: self.aws_account_id,
            topic_id: self.topic_id,
            dataset_id: self.dataset_id,
        })
    }
}
