// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A uniquely identified group of stream records within a stream.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Shard {
    /// <p>The system-generated identifier for this shard.</p>
    pub shard_id: ::std::option::Option<::std::string::String>,
    /// <p>The range of possible sequence numbers for the shard.</p>
    pub sequence_number_range: ::std::option::Option<crate::types::SequenceNumberRange>,
    /// <p>The shard ID of the current shard's parent.</p>
    pub parent_shard_id: ::std::option::Option<::std::string::String>,
}
impl Shard {
    /// <p>The system-generated identifier for this shard.</p>
    pub fn shard_id(&self) -> ::std::option::Option<&str> {
        self.shard_id.as_deref()
    }
    /// <p>The range of possible sequence numbers for the shard.</p>
    pub fn sequence_number_range(&self) -> ::std::option::Option<&crate::types::SequenceNumberRange> {
        self.sequence_number_range.as_ref()
    }
    /// <p>The shard ID of the current shard's parent.</p>
    pub fn parent_shard_id(&self) -> ::std::option::Option<&str> {
        self.parent_shard_id.as_deref()
    }
}
impl Shard {
    /// Creates a new builder-style object to manufacture [`Shard`](crate::types::Shard).
    pub fn builder() -> crate::types::builders::ShardBuilder {
        crate::types::builders::ShardBuilder::default()
    }
}

/// A builder for [`Shard`](crate::types::Shard).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ShardBuilder {
    pub(crate) shard_id: ::std::option::Option<::std::string::String>,
    pub(crate) sequence_number_range: ::std::option::Option<crate::types::SequenceNumberRange>,
    pub(crate) parent_shard_id: ::std::option::Option<::std::string::String>,
}
impl ShardBuilder {
    /// <p>The system-generated identifier for this shard.</p>
    pub fn shard_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.shard_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated identifier for this shard.</p>
    pub fn set_shard_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.shard_id = input;
        self
    }
    /// <p>The system-generated identifier for this shard.</p>
    pub fn get_shard_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.shard_id
    }
    /// <p>The range of possible sequence numbers for the shard.</p>
    pub fn sequence_number_range(mut self, input: crate::types::SequenceNumberRange) -> Self {
        self.sequence_number_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>The range of possible sequence numbers for the shard.</p>
    pub fn set_sequence_number_range(mut self, input: ::std::option::Option<crate::types::SequenceNumberRange>) -> Self {
        self.sequence_number_range = input;
        self
    }
    /// <p>The range of possible sequence numbers for the shard.</p>
    pub fn get_sequence_number_range(&self) -> &::std::option::Option<crate::types::SequenceNumberRange> {
        &self.sequence_number_range
    }
    /// <p>The shard ID of the current shard's parent.</p>
    pub fn parent_shard_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_shard_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The shard ID of the current shard's parent.</p>
    pub fn set_parent_shard_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_shard_id = input;
        self
    }
    /// <p>The shard ID of the current shard's parent.</p>
    pub fn get_parent_shard_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_shard_id
    }
    /// Consumes the builder and constructs a [`Shard`](crate::types::Shard).
    pub fn build(self) -> crate::types::Shard {
        crate::types::Shard {
            shard_id: self.shard_id,
            sequence_number_range: self.sequence_number_range,
            parent_shard_id: self.parent_shard_id,
        }
    }
}
