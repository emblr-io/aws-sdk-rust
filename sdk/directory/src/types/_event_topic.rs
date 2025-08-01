// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about Amazon SNS topic and Directory Service directory associations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EventTopic {
    /// <p>The Directory ID of an Directory Service directory that will publish status messages to an Amazon SNS topic.</p>
    pub directory_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of an Amazon SNS topic the receives status messages from the directory.</p>
    pub topic_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon SNS topic ARN (Amazon Resource Name).</p>
    pub topic_arn: ::std::option::Option<::std::string::String>,
    /// <p>The date and time of when you associated your directory with the Amazon SNS topic.</p>
    pub created_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The topic registration status.</p>
    pub status: ::std::option::Option<crate::types::TopicStatus>,
}
impl EventTopic {
    /// <p>The Directory ID of an Directory Service directory that will publish status messages to an Amazon SNS topic.</p>
    pub fn directory_id(&self) -> ::std::option::Option<&str> {
        self.directory_id.as_deref()
    }
    /// <p>The name of an Amazon SNS topic the receives status messages from the directory.</p>
    pub fn topic_name(&self) -> ::std::option::Option<&str> {
        self.topic_name.as_deref()
    }
    /// <p>The Amazon SNS topic ARN (Amazon Resource Name).</p>
    pub fn topic_arn(&self) -> ::std::option::Option<&str> {
        self.topic_arn.as_deref()
    }
    /// <p>The date and time of when you associated your directory with the Amazon SNS topic.</p>
    pub fn created_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_date_time.as_ref()
    }
    /// <p>The topic registration status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::TopicStatus> {
        self.status.as_ref()
    }
}
impl EventTopic {
    /// Creates a new builder-style object to manufacture [`EventTopic`](crate::types::EventTopic).
    pub fn builder() -> crate::types::builders::EventTopicBuilder {
        crate::types::builders::EventTopicBuilder::default()
    }
}

/// A builder for [`EventTopic`](crate::types::EventTopic).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EventTopicBuilder {
    pub(crate) directory_id: ::std::option::Option<::std::string::String>,
    pub(crate) topic_name: ::std::option::Option<::std::string::String>,
    pub(crate) topic_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::TopicStatus>,
}
impl EventTopicBuilder {
    /// <p>The Directory ID of an Directory Service directory that will publish status messages to an Amazon SNS topic.</p>
    pub fn directory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Directory ID of an Directory Service directory that will publish status messages to an Amazon SNS topic.</p>
    pub fn set_directory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_id = input;
        self
    }
    /// <p>The Directory ID of an Directory Service directory that will publish status messages to an Amazon SNS topic.</p>
    pub fn get_directory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_id
    }
    /// <p>The name of an Amazon SNS topic the receives status messages from the directory.</p>
    pub fn topic_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of an Amazon SNS topic the receives status messages from the directory.</p>
    pub fn set_topic_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_name = input;
        self
    }
    /// <p>The name of an Amazon SNS topic the receives status messages from the directory.</p>
    pub fn get_topic_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_name
    }
    /// <p>The Amazon SNS topic ARN (Amazon Resource Name).</p>
    pub fn topic_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon SNS topic ARN (Amazon Resource Name).</p>
    pub fn set_topic_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_arn = input;
        self
    }
    /// <p>The Amazon SNS topic ARN (Amazon Resource Name).</p>
    pub fn get_topic_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_arn
    }
    /// <p>The date and time of when you associated your directory with the Amazon SNS topic.</p>
    pub fn created_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time of when you associated your directory with the Amazon SNS topic.</p>
    pub fn set_created_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_date_time = input;
        self
    }
    /// <p>The date and time of when you associated your directory with the Amazon SNS topic.</p>
    pub fn get_created_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_date_time
    }
    /// <p>The topic registration status.</p>
    pub fn status(mut self, input: crate::types::TopicStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The topic registration status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::TopicStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The topic registration status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::TopicStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`EventTopic`](crate::types::EventTopic).
    pub fn build(self) -> crate::types::EventTopic {
        crate::types::EventTopic {
            directory_id: self.directory_id,
            topic_name: self.topic_name,
            topic_arn: self.topic_arn,
            created_date_time: self.created_date_time,
            status: self.status,
        }
    }
}
