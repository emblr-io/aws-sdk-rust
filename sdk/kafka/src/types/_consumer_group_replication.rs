// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about consumer group replication.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConsumerGroupReplication {
    /// <p>List of regular expression patterns indicating the consumer groups that should not be replicated.</p>
    pub consumer_groups_to_exclude: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>List of regular expression patterns indicating the consumer groups to copy.</p>
    pub consumer_groups_to_replicate: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Enables synchronization of consumer groups to target cluster.</p>
    pub detect_and_copy_new_consumer_groups: ::std::option::Option<bool>,
    /// <p>Enables synchronization of consumer group offsets to target cluster. The translated offsets will be written to topic __consumer_offsets.</p>
    pub synchronise_consumer_group_offsets: ::std::option::Option<bool>,
}
impl ConsumerGroupReplication {
    /// <p>List of regular expression patterns indicating the consumer groups that should not be replicated.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.consumer_groups_to_exclude.is_none()`.
    pub fn consumer_groups_to_exclude(&self) -> &[::std::string::String] {
        self.consumer_groups_to_exclude.as_deref().unwrap_or_default()
    }
    /// <p>List of regular expression patterns indicating the consumer groups to copy.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.consumer_groups_to_replicate.is_none()`.
    pub fn consumer_groups_to_replicate(&self) -> &[::std::string::String] {
        self.consumer_groups_to_replicate.as_deref().unwrap_or_default()
    }
    /// <p>Enables synchronization of consumer groups to target cluster.</p>
    pub fn detect_and_copy_new_consumer_groups(&self) -> ::std::option::Option<bool> {
        self.detect_and_copy_new_consumer_groups
    }
    /// <p>Enables synchronization of consumer group offsets to target cluster. The translated offsets will be written to topic __consumer_offsets.</p>
    pub fn synchronise_consumer_group_offsets(&self) -> ::std::option::Option<bool> {
        self.synchronise_consumer_group_offsets
    }
}
impl ConsumerGroupReplication {
    /// Creates a new builder-style object to manufacture [`ConsumerGroupReplication`](crate::types::ConsumerGroupReplication).
    pub fn builder() -> crate::types::builders::ConsumerGroupReplicationBuilder {
        crate::types::builders::ConsumerGroupReplicationBuilder::default()
    }
}

/// A builder for [`ConsumerGroupReplication`](crate::types::ConsumerGroupReplication).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConsumerGroupReplicationBuilder {
    pub(crate) consumer_groups_to_exclude: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) consumer_groups_to_replicate: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) detect_and_copy_new_consumer_groups: ::std::option::Option<bool>,
    pub(crate) synchronise_consumer_group_offsets: ::std::option::Option<bool>,
}
impl ConsumerGroupReplicationBuilder {
    /// Appends an item to `consumer_groups_to_exclude`.
    ///
    /// To override the contents of this collection use [`set_consumer_groups_to_exclude`](Self::set_consumer_groups_to_exclude).
    ///
    /// <p>List of regular expression patterns indicating the consumer groups that should not be replicated.</p>
    pub fn consumer_groups_to_exclude(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.consumer_groups_to_exclude.unwrap_or_default();
        v.push(input.into());
        self.consumer_groups_to_exclude = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of regular expression patterns indicating the consumer groups that should not be replicated.</p>
    pub fn set_consumer_groups_to_exclude(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.consumer_groups_to_exclude = input;
        self
    }
    /// <p>List of regular expression patterns indicating the consumer groups that should not be replicated.</p>
    pub fn get_consumer_groups_to_exclude(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.consumer_groups_to_exclude
    }
    /// Appends an item to `consumer_groups_to_replicate`.
    ///
    /// To override the contents of this collection use [`set_consumer_groups_to_replicate`](Self::set_consumer_groups_to_replicate).
    ///
    /// <p>List of regular expression patterns indicating the consumer groups to copy.</p>
    pub fn consumer_groups_to_replicate(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.consumer_groups_to_replicate.unwrap_or_default();
        v.push(input.into());
        self.consumer_groups_to_replicate = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of regular expression patterns indicating the consumer groups to copy.</p>
    pub fn set_consumer_groups_to_replicate(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.consumer_groups_to_replicate = input;
        self
    }
    /// <p>List of regular expression patterns indicating the consumer groups to copy.</p>
    pub fn get_consumer_groups_to_replicate(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.consumer_groups_to_replicate
    }
    /// <p>Enables synchronization of consumer groups to target cluster.</p>
    pub fn detect_and_copy_new_consumer_groups(mut self, input: bool) -> Self {
        self.detect_and_copy_new_consumer_groups = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables synchronization of consumer groups to target cluster.</p>
    pub fn set_detect_and_copy_new_consumer_groups(mut self, input: ::std::option::Option<bool>) -> Self {
        self.detect_and_copy_new_consumer_groups = input;
        self
    }
    /// <p>Enables synchronization of consumer groups to target cluster.</p>
    pub fn get_detect_and_copy_new_consumer_groups(&self) -> &::std::option::Option<bool> {
        &self.detect_and_copy_new_consumer_groups
    }
    /// <p>Enables synchronization of consumer group offsets to target cluster. The translated offsets will be written to topic __consumer_offsets.</p>
    pub fn synchronise_consumer_group_offsets(mut self, input: bool) -> Self {
        self.synchronise_consumer_group_offsets = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables synchronization of consumer group offsets to target cluster. The translated offsets will be written to topic __consumer_offsets.</p>
    pub fn set_synchronise_consumer_group_offsets(mut self, input: ::std::option::Option<bool>) -> Self {
        self.synchronise_consumer_group_offsets = input;
        self
    }
    /// <p>Enables synchronization of consumer group offsets to target cluster. The translated offsets will be written to topic __consumer_offsets.</p>
    pub fn get_synchronise_consumer_group_offsets(&self) -> &::std::option::Option<bool> {
        &self.synchronise_consumer_group_offsets
    }
    /// Consumes the builder and constructs a [`ConsumerGroupReplication`](crate::types::ConsumerGroupReplication).
    pub fn build(self) -> crate::types::ConsumerGroupReplication {
        crate::types::ConsumerGroupReplication {
            consumer_groups_to_exclude: self.consumer_groups_to_exclude,
            consumer_groups_to_replicate: self.consumer_groups_to_replicate,
            detect_and_copy_new_consumer_groups: self.detect_and_copy_new_consumer_groups,
            synchronise_consumer_group_offsets: self.synchronise_consumer_group_offsets,
        }
    }
}
