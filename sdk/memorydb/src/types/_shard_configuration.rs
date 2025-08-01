// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Shard configuration options. Each shard configuration has the following: Slots and ReplicaCount.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ShardConfiguration {
    /// <p>A string that specifies the keyspace for a particular node group. Keyspaces range from 0 to 16,383. The string is in the format startkey-endkey.</p>
    pub slots: ::std::option::Option<::std::string::String>,
    /// <p>The number of read replica nodes in this shard.</p>
    pub replica_count: ::std::option::Option<i32>,
}
impl ShardConfiguration {
    /// <p>A string that specifies the keyspace for a particular node group. Keyspaces range from 0 to 16,383. The string is in the format startkey-endkey.</p>
    pub fn slots(&self) -> ::std::option::Option<&str> {
        self.slots.as_deref()
    }
    /// <p>The number of read replica nodes in this shard.</p>
    pub fn replica_count(&self) -> ::std::option::Option<i32> {
        self.replica_count
    }
}
impl ShardConfiguration {
    /// Creates a new builder-style object to manufacture [`ShardConfiguration`](crate::types::ShardConfiguration).
    pub fn builder() -> crate::types::builders::ShardConfigurationBuilder {
        crate::types::builders::ShardConfigurationBuilder::default()
    }
}

/// A builder for [`ShardConfiguration`](crate::types::ShardConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ShardConfigurationBuilder {
    pub(crate) slots: ::std::option::Option<::std::string::String>,
    pub(crate) replica_count: ::std::option::Option<i32>,
}
impl ShardConfigurationBuilder {
    /// <p>A string that specifies the keyspace for a particular node group. Keyspaces range from 0 to 16,383. The string is in the format startkey-endkey.</p>
    pub fn slots(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.slots = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that specifies the keyspace for a particular node group. Keyspaces range from 0 to 16,383. The string is in the format startkey-endkey.</p>
    pub fn set_slots(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.slots = input;
        self
    }
    /// <p>A string that specifies the keyspace for a particular node group. Keyspaces range from 0 to 16,383. The string is in the format startkey-endkey.</p>
    pub fn get_slots(&self) -> &::std::option::Option<::std::string::String> {
        &self.slots
    }
    /// <p>The number of read replica nodes in this shard.</p>
    pub fn replica_count(mut self, input: i32) -> Self {
        self.replica_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of read replica nodes in this shard.</p>
    pub fn set_replica_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.replica_count = input;
        self
    }
    /// <p>The number of read replica nodes in this shard.</p>
    pub fn get_replica_count(&self) -> &::std::option::Option<i32> {
        &self.replica_count
    }
    /// Consumes the builder and constructs a [`ShardConfiguration`](crate::types::ShardConfiguration).
    pub fn build(self) -> crate::types::ShardConfiguration {
        crate::types::ShardConfiguration {
            slots: self.slots,
            replica_count: self.replica_count,
        }
    }
}
