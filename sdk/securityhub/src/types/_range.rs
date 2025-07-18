// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Identifies where the sensitive data begins and ends.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Range {
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub start: ::std::option::Option<i64>,
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub end: ::std::option::Option<i64>,
    /// <p>In the line where the sensitive data starts, the column within the line where the sensitive data starts.</p>
    pub start_column: ::std::option::Option<i64>,
}
impl Range {
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub fn start(&self) -> ::std::option::Option<i64> {
        self.start
    }
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub fn end(&self) -> ::std::option::Option<i64> {
        self.end
    }
    /// <p>In the line where the sensitive data starts, the column within the line where the sensitive data starts.</p>
    pub fn start_column(&self) -> ::std::option::Option<i64> {
        self.start_column
    }
}
impl Range {
    /// Creates a new builder-style object to manufacture [`Range`](crate::types::Range).
    pub fn builder() -> crate::types::builders::RangeBuilder {
        crate::types::builders::RangeBuilder::default()
    }
}

/// A builder for [`Range`](crate::types::Range).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RangeBuilder {
    pub(crate) start: ::std::option::Option<i64>,
    pub(crate) end: ::std::option::Option<i64>,
    pub(crate) start_column: ::std::option::Option<i64>,
}
impl RangeBuilder {
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub fn start(mut self, input: i64) -> Self {
        self.start = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub fn set_start(mut self, input: ::std::option::Option<i64>) -> Self {
        self.start = input;
        self
    }
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub fn get_start(&self) -> &::std::option::Option<i64> {
        &self.start
    }
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub fn end(mut self, input: i64) -> Self {
        self.end = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub fn set_end(mut self, input: ::std::option::Option<i64>) -> Self {
        self.end = input;
        self
    }
    /// <p>The number of lines (for a line range) or characters (for an offset range) from the beginning of the file to the end of the sensitive data.</p>
    pub fn get_end(&self) -> &::std::option::Option<i64> {
        &self.end
    }
    /// <p>In the line where the sensitive data starts, the column within the line where the sensitive data starts.</p>
    pub fn start_column(mut self, input: i64) -> Self {
        self.start_column = ::std::option::Option::Some(input);
        self
    }
    /// <p>In the line where the sensitive data starts, the column within the line where the sensitive data starts.</p>
    pub fn set_start_column(mut self, input: ::std::option::Option<i64>) -> Self {
        self.start_column = input;
        self
    }
    /// <p>In the line where the sensitive data starts, the column within the line where the sensitive data starts.</p>
    pub fn get_start_column(&self) -> &::std::option::Option<i64> {
        &self.start_column
    }
    /// Consumes the builder and constructs a [`Range`](crate::types::Range).
    pub fn build(self) -> crate::types::Range {
        crate::types::Range {
            start: self.start,
            end: self.end,
            start_column: self.start_column,
        }
    }
}
