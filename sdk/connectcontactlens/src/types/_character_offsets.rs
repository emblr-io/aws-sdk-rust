// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>For characters that were detected as issues, where they occur in the transcript.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CharacterOffsets {
    /// <p>The beginning of the issue.</p>
    pub begin_offset_char: ::std::option::Option<i32>,
    /// <p>The end of the issue.</p>
    pub end_offset_char: ::std::option::Option<i32>,
}
impl CharacterOffsets {
    /// <p>The beginning of the issue.</p>
    pub fn begin_offset_char(&self) -> ::std::option::Option<i32> {
        self.begin_offset_char
    }
    /// <p>The end of the issue.</p>
    pub fn end_offset_char(&self) -> ::std::option::Option<i32> {
        self.end_offset_char
    }
}
impl CharacterOffsets {
    /// Creates a new builder-style object to manufacture [`CharacterOffsets`](crate::types::CharacterOffsets).
    pub fn builder() -> crate::types::builders::CharacterOffsetsBuilder {
        crate::types::builders::CharacterOffsetsBuilder::default()
    }
}

/// A builder for [`CharacterOffsets`](crate::types::CharacterOffsets).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CharacterOffsetsBuilder {
    pub(crate) begin_offset_char: ::std::option::Option<i32>,
    pub(crate) end_offset_char: ::std::option::Option<i32>,
}
impl CharacterOffsetsBuilder {
    /// <p>The beginning of the issue.</p>
    /// This field is required.
    pub fn begin_offset_char(mut self, input: i32) -> Self {
        self.begin_offset_char = ::std::option::Option::Some(input);
        self
    }
    /// <p>The beginning of the issue.</p>
    pub fn set_begin_offset_char(mut self, input: ::std::option::Option<i32>) -> Self {
        self.begin_offset_char = input;
        self
    }
    /// <p>The beginning of the issue.</p>
    pub fn get_begin_offset_char(&self) -> &::std::option::Option<i32> {
        &self.begin_offset_char
    }
    /// <p>The end of the issue.</p>
    /// This field is required.
    pub fn end_offset_char(mut self, input: i32) -> Self {
        self.end_offset_char = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end of the issue.</p>
    pub fn set_end_offset_char(mut self, input: ::std::option::Option<i32>) -> Self {
        self.end_offset_char = input;
        self
    }
    /// <p>The end of the issue.</p>
    pub fn get_end_offset_char(&self) -> &::std::option::Option<i32> {
        &self.end_offset_char
    }
    /// Consumes the builder and constructs a [`CharacterOffsets`](crate::types::CharacterOffsets).
    pub fn build(self) -> crate::types::CharacterOffsets {
        crate::types::CharacterOffsets {
            begin_offset_char: self.begin_offset_char,
            end_offset_char: self.end_offset_char,
        }
    }
}
