// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about topic replication.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TopicReplication {
    /// <p>Whether to periodically configure remote topic ACLs to match their corresponding upstream topics.</p>
    pub copy_access_control_lists_for_topics: ::std::option::Option<bool>,
    /// <p>Whether to periodically configure remote topics to match their corresponding upstream topics.</p>
    pub copy_topic_configurations: ::std::option::Option<bool>,
    /// <p>Whether to periodically check for new topics and partitions.</p>
    pub detect_and_copy_new_topics: ::std::option::Option<bool>,
    /// <p>Configuration for specifying the position in the topics to start replicating from.</p>
    pub starting_position: ::std::option::Option<crate::types::ReplicationStartingPosition>,
    /// <p>Configuration for specifying replicated topic names should be the same as their corresponding upstream topics or prefixed with source cluster alias.</p>
    pub topic_name_configuration: ::std::option::Option<crate::types::ReplicationTopicNameConfiguration>,
    /// <p>List of regular expression patterns indicating the topics that should not be replicated.</p>
    pub topics_to_exclude: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>List of regular expression patterns indicating the topics to copy.</p>
    pub topics_to_replicate: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TopicReplication {
    /// <p>Whether to periodically configure remote topic ACLs to match their corresponding upstream topics.</p>
    pub fn copy_access_control_lists_for_topics(&self) -> ::std::option::Option<bool> {
        self.copy_access_control_lists_for_topics
    }
    /// <p>Whether to periodically configure remote topics to match their corresponding upstream topics.</p>
    pub fn copy_topic_configurations(&self) -> ::std::option::Option<bool> {
        self.copy_topic_configurations
    }
    /// <p>Whether to periodically check for new topics and partitions.</p>
    pub fn detect_and_copy_new_topics(&self) -> ::std::option::Option<bool> {
        self.detect_and_copy_new_topics
    }
    /// <p>Configuration for specifying the position in the topics to start replicating from.</p>
    pub fn starting_position(&self) -> ::std::option::Option<&crate::types::ReplicationStartingPosition> {
        self.starting_position.as_ref()
    }
    /// <p>Configuration for specifying replicated topic names should be the same as their corresponding upstream topics or prefixed with source cluster alias.</p>
    pub fn topic_name_configuration(&self) -> ::std::option::Option<&crate::types::ReplicationTopicNameConfiguration> {
        self.topic_name_configuration.as_ref()
    }
    /// <p>List of regular expression patterns indicating the topics that should not be replicated.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.topics_to_exclude.is_none()`.
    pub fn topics_to_exclude(&self) -> &[::std::string::String] {
        self.topics_to_exclude.as_deref().unwrap_or_default()
    }
    /// <p>List of regular expression patterns indicating the topics to copy.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.topics_to_replicate.is_none()`.
    pub fn topics_to_replicate(&self) -> &[::std::string::String] {
        self.topics_to_replicate.as_deref().unwrap_or_default()
    }
}
impl TopicReplication {
    /// Creates a new builder-style object to manufacture [`TopicReplication`](crate::types::TopicReplication).
    pub fn builder() -> crate::types::builders::TopicReplicationBuilder {
        crate::types::builders::TopicReplicationBuilder::default()
    }
}

/// A builder for [`TopicReplication`](crate::types::TopicReplication).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TopicReplicationBuilder {
    pub(crate) copy_access_control_lists_for_topics: ::std::option::Option<bool>,
    pub(crate) copy_topic_configurations: ::std::option::Option<bool>,
    pub(crate) detect_and_copy_new_topics: ::std::option::Option<bool>,
    pub(crate) starting_position: ::std::option::Option<crate::types::ReplicationStartingPosition>,
    pub(crate) topic_name_configuration: ::std::option::Option<crate::types::ReplicationTopicNameConfiguration>,
    pub(crate) topics_to_exclude: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) topics_to_replicate: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TopicReplicationBuilder {
    /// <p>Whether to periodically configure remote topic ACLs to match their corresponding upstream topics.</p>
    pub fn copy_access_control_lists_for_topics(mut self, input: bool) -> Self {
        self.copy_access_control_lists_for_topics = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to periodically configure remote topic ACLs to match their corresponding upstream topics.</p>
    pub fn set_copy_access_control_lists_for_topics(mut self, input: ::std::option::Option<bool>) -> Self {
        self.copy_access_control_lists_for_topics = input;
        self
    }
    /// <p>Whether to periodically configure remote topic ACLs to match their corresponding upstream topics.</p>
    pub fn get_copy_access_control_lists_for_topics(&self) -> &::std::option::Option<bool> {
        &self.copy_access_control_lists_for_topics
    }
    /// <p>Whether to periodically configure remote topics to match their corresponding upstream topics.</p>
    pub fn copy_topic_configurations(mut self, input: bool) -> Self {
        self.copy_topic_configurations = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to periodically configure remote topics to match their corresponding upstream topics.</p>
    pub fn set_copy_topic_configurations(mut self, input: ::std::option::Option<bool>) -> Self {
        self.copy_topic_configurations = input;
        self
    }
    /// <p>Whether to periodically configure remote topics to match their corresponding upstream topics.</p>
    pub fn get_copy_topic_configurations(&self) -> &::std::option::Option<bool> {
        &self.copy_topic_configurations
    }
    /// <p>Whether to periodically check for new topics and partitions.</p>
    pub fn detect_and_copy_new_topics(mut self, input: bool) -> Self {
        self.detect_and_copy_new_topics = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to periodically check for new topics and partitions.</p>
    pub fn set_detect_and_copy_new_topics(mut self, input: ::std::option::Option<bool>) -> Self {
        self.detect_and_copy_new_topics = input;
        self
    }
    /// <p>Whether to periodically check for new topics and partitions.</p>
    pub fn get_detect_and_copy_new_topics(&self) -> &::std::option::Option<bool> {
        &self.detect_and_copy_new_topics
    }
    /// <p>Configuration for specifying the position in the topics to start replicating from.</p>
    pub fn starting_position(mut self, input: crate::types::ReplicationStartingPosition) -> Self {
        self.starting_position = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration for specifying the position in the topics to start replicating from.</p>
    pub fn set_starting_position(mut self, input: ::std::option::Option<crate::types::ReplicationStartingPosition>) -> Self {
        self.starting_position = input;
        self
    }
    /// <p>Configuration for specifying the position in the topics to start replicating from.</p>
    pub fn get_starting_position(&self) -> &::std::option::Option<crate::types::ReplicationStartingPosition> {
        &self.starting_position
    }
    /// <p>Configuration for specifying replicated topic names should be the same as their corresponding upstream topics or prefixed with source cluster alias.</p>
    pub fn topic_name_configuration(mut self, input: crate::types::ReplicationTopicNameConfiguration) -> Self {
        self.topic_name_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration for specifying replicated topic names should be the same as their corresponding upstream topics or prefixed with source cluster alias.</p>
    pub fn set_topic_name_configuration(mut self, input: ::std::option::Option<crate::types::ReplicationTopicNameConfiguration>) -> Self {
        self.topic_name_configuration = input;
        self
    }
    /// <p>Configuration for specifying replicated topic names should be the same as their corresponding upstream topics or prefixed with source cluster alias.</p>
    pub fn get_topic_name_configuration(&self) -> &::std::option::Option<crate::types::ReplicationTopicNameConfiguration> {
        &self.topic_name_configuration
    }
    /// Appends an item to `topics_to_exclude`.
    ///
    /// To override the contents of this collection use [`set_topics_to_exclude`](Self::set_topics_to_exclude).
    ///
    /// <p>List of regular expression patterns indicating the topics that should not be replicated.</p>
    pub fn topics_to_exclude(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.topics_to_exclude.unwrap_or_default();
        v.push(input.into());
        self.topics_to_exclude = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of regular expression patterns indicating the topics that should not be replicated.</p>
    pub fn set_topics_to_exclude(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.topics_to_exclude = input;
        self
    }
    /// <p>List of regular expression patterns indicating the topics that should not be replicated.</p>
    pub fn get_topics_to_exclude(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.topics_to_exclude
    }
    /// Appends an item to `topics_to_replicate`.
    ///
    /// To override the contents of this collection use [`set_topics_to_replicate`](Self::set_topics_to_replicate).
    ///
    /// <p>List of regular expression patterns indicating the topics to copy.</p>
    pub fn topics_to_replicate(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.topics_to_replicate.unwrap_or_default();
        v.push(input.into());
        self.topics_to_replicate = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of regular expression patterns indicating the topics to copy.</p>
    pub fn set_topics_to_replicate(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.topics_to_replicate = input;
        self
    }
    /// <p>List of regular expression patterns indicating the topics to copy.</p>
    pub fn get_topics_to_replicate(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.topics_to_replicate
    }
    /// Consumes the builder and constructs a [`TopicReplication`](crate::types::TopicReplication).
    pub fn build(self) -> crate::types::TopicReplication {
        crate::types::TopicReplication {
            copy_access_control_lists_for_topics: self.copy_access_control_lists_for_topics,
            copy_topic_configurations: self.copy_topic_configurations,
            detect_and_copy_new_topics: self.detect_and_copy_new_topics,
            starting_position: self.starting_position,
            topic_name_configuration: self.topic_name_configuration,
            topics_to_exclude: self.topics_to_exclude,
            topics_to_replicate: self.topics_to_replicate,
        }
    }
}
