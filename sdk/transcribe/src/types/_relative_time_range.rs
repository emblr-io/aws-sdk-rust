// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A time range, in percentage, between two points in your media file.</p>
/// <p>You can use <code>StartPercentage</code> and <code>EndPercentage</code> to search a custom segment. For example, setting <code>StartPercentage</code> to 10 and <code>EndPercentage</code> to 50 only searches for your specified criteria in the audio contained between the 10 percent mark and the 50 percent mark of your media file.</p>
/// <p>You can use also <code>First</code> to search from the start of the media file until the time that you specify. Or use <code>Last</code> to search from the time that you specify until the end of the media file. For example, setting <code>First</code> to 10 only searches for your specified criteria in the audio contained in the first 10 percent of the media file.</p>
/// <p>If you prefer to use milliseconds instead of percentage, see .</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RelativeTimeRange {
    /// <p>The time, in percentage, when Amazon Transcribe starts searching for the specified criteria in your media file. If you include <code>StartPercentage</code> in your request, you must also include <code>EndPercentage</code>.</p>
    pub start_percentage: ::std::option::Option<i32>,
    /// <p>The time, in percentage, when Amazon Transcribe stops searching for the specified criteria in your media file. If you include <code>EndPercentage</code> in your request, you must also include <code>StartPercentage</code>.</p>
    pub end_percentage: ::std::option::Option<i32>,
    /// <p>The time, in percentage, from the start of your media file until the specified value. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub first: ::std::option::Option<i32>,
    /// <p>The time, in percentage, from the specified value until the end of your media file. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub last: ::std::option::Option<i32>,
}
impl RelativeTimeRange {
    /// <p>The time, in percentage, when Amazon Transcribe starts searching for the specified criteria in your media file. If you include <code>StartPercentage</code> in your request, you must also include <code>EndPercentage</code>.</p>
    pub fn start_percentage(&self) -> ::std::option::Option<i32> {
        self.start_percentage
    }
    /// <p>The time, in percentage, when Amazon Transcribe stops searching for the specified criteria in your media file. If you include <code>EndPercentage</code> in your request, you must also include <code>StartPercentage</code>.</p>
    pub fn end_percentage(&self) -> ::std::option::Option<i32> {
        self.end_percentage
    }
    /// <p>The time, in percentage, from the start of your media file until the specified value. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub fn first(&self) -> ::std::option::Option<i32> {
        self.first
    }
    /// <p>The time, in percentage, from the specified value until the end of your media file. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub fn last(&self) -> ::std::option::Option<i32> {
        self.last
    }
}
impl RelativeTimeRange {
    /// Creates a new builder-style object to manufacture [`RelativeTimeRange`](crate::types::RelativeTimeRange).
    pub fn builder() -> crate::types::builders::RelativeTimeRangeBuilder {
        crate::types::builders::RelativeTimeRangeBuilder::default()
    }
}

/// A builder for [`RelativeTimeRange`](crate::types::RelativeTimeRange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RelativeTimeRangeBuilder {
    pub(crate) start_percentage: ::std::option::Option<i32>,
    pub(crate) end_percentage: ::std::option::Option<i32>,
    pub(crate) first: ::std::option::Option<i32>,
    pub(crate) last: ::std::option::Option<i32>,
}
impl RelativeTimeRangeBuilder {
    /// <p>The time, in percentage, when Amazon Transcribe starts searching for the specified criteria in your media file. If you include <code>StartPercentage</code> in your request, you must also include <code>EndPercentage</code>.</p>
    pub fn start_percentage(mut self, input: i32) -> Self {
        self.start_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in percentage, when Amazon Transcribe starts searching for the specified criteria in your media file. If you include <code>StartPercentage</code> in your request, you must also include <code>EndPercentage</code>.</p>
    pub fn set_start_percentage(mut self, input: ::std::option::Option<i32>) -> Self {
        self.start_percentage = input;
        self
    }
    /// <p>The time, in percentage, when Amazon Transcribe starts searching for the specified criteria in your media file. If you include <code>StartPercentage</code> in your request, you must also include <code>EndPercentage</code>.</p>
    pub fn get_start_percentage(&self) -> &::std::option::Option<i32> {
        &self.start_percentage
    }
    /// <p>The time, in percentage, when Amazon Transcribe stops searching for the specified criteria in your media file. If you include <code>EndPercentage</code> in your request, you must also include <code>StartPercentage</code>.</p>
    pub fn end_percentage(mut self, input: i32) -> Self {
        self.end_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in percentage, when Amazon Transcribe stops searching for the specified criteria in your media file. If you include <code>EndPercentage</code> in your request, you must also include <code>StartPercentage</code>.</p>
    pub fn set_end_percentage(mut self, input: ::std::option::Option<i32>) -> Self {
        self.end_percentage = input;
        self
    }
    /// <p>The time, in percentage, when Amazon Transcribe stops searching for the specified criteria in your media file. If you include <code>EndPercentage</code> in your request, you must also include <code>StartPercentage</code>.</p>
    pub fn get_end_percentage(&self) -> &::std::option::Option<i32> {
        &self.end_percentage
    }
    /// <p>The time, in percentage, from the start of your media file until the specified value. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub fn first(mut self, input: i32) -> Self {
        self.first = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in percentage, from the start of your media file until the specified value. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub fn set_first(mut self, input: ::std::option::Option<i32>) -> Self {
        self.first = input;
        self
    }
    /// <p>The time, in percentage, from the start of your media file until the specified value. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub fn get_first(&self) -> &::std::option::Option<i32> {
        &self.first
    }
    /// <p>The time, in percentage, from the specified value until the end of your media file. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub fn last(mut self, input: i32) -> Self {
        self.last = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in percentage, from the specified value until the end of your media file. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub fn set_last(mut self, input: ::std::option::Option<i32>) -> Self {
        self.last = input;
        self
    }
    /// <p>The time, in percentage, from the specified value until the end of your media file. Amazon Transcribe searches for your specified criteria in this time segment.</p>
    pub fn get_last(&self) -> &::std::option::Option<i32> {
        &self.last
    }
    /// Consumes the builder and constructs a [`RelativeTimeRange`](crate::types::RelativeTimeRange).
    pub fn build(self) -> crate::types::RelativeTimeRange {
        crate::types::RelativeTimeRange {
            start_percentage: self.start_percentage,
            end_percentage: self.end_percentage,
            first: self.first,
            last: self.last,
        }
    }
}
