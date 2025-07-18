// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Offset specification to describe highlighting of document excerpts for rendering search results and recommendations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Highlight {
    /// <p>The offset for the start of the highlight.</p>
    pub begin_offset_inclusive: i32,
    /// <p>The offset for the end of the highlight.</p>
    pub end_offset_exclusive: i32,
}
impl Highlight {
    /// <p>The offset for the start of the highlight.</p>
    pub fn begin_offset_inclusive(&self) -> i32 {
        self.begin_offset_inclusive
    }
    /// <p>The offset for the end of the highlight.</p>
    pub fn end_offset_exclusive(&self) -> i32 {
        self.end_offset_exclusive
    }
}
impl Highlight {
    /// Creates a new builder-style object to manufacture [`Highlight`](crate::types::Highlight).
    pub fn builder() -> crate::types::builders::HighlightBuilder {
        crate::types::builders::HighlightBuilder::default()
    }
}

/// A builder for [`Highlight`](crate::types::Highlight).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HighlightBuilder {
    pub(crate) begin_offset_inclusive: ::std::option::Option<i32>,
    pub(crate) end_offset_exclusive: ::std::option::Option<i32>,
}
impl HighlightBuilder {
    /// <p>The offset for the start of the highlight.</p>
    pub fn begin_offset_inclusive(mut self, input: i32) -> Self {
        self.begin_offset_inclusive = ::std::option::Option::Some(input);
        self
    }
    /// <p>The offset for the start of the highlight.</p>
    pub fn set_begin_offset_inclusive(mut self, input: ::std::option::Option<i32>) -> Self {
        self.begin_offset_inclusive = input;
        self
    }
    /// <p>The offset for the start of the highlight.</p>
    pub fn get_begin_offset_inclusive(&self) -> &::std::option::Option<i32> {
        &self.begin_offset_inclusive
    }
    /// <p>The offset for the end of the highlight.</p>
    pub fn end_offset_exclusive(mut self, input: i32) -> Self {
        self.end_offset_exclusive = ::std::option::Option::Some(input);
        self
    }
    /// <p>The offset for the end of the highlight.</p>
    pub fn set_end_offset_exclusive(mut self, input: ::std::option::Option<i32>) -> Self {
        self.end_offset_exclusive = input;
        self
    }
    /// <p>The offset for the end of the highlight.</p>
    pub fn get_end_offset_exclusive(&self) -> &::std::option::Option<i32> {
        &self.end_offset_exclusive
    }
    /// Consumes the builder and constructs a [`Highlight`](crate::types::Highlight).
    pub fn build(self) -> crate::types::Highlight {
        crate::types::Highlight {
            begin_offset_inclusive: self.begin_offset_inclusive.unwrap_or_default(),
            end_offset_exclusive: self.end_offset_exclusive.unwrap_or_default(),
        }
    }
}
