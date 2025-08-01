// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The range of timestamps for which to return fragments.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClipTimestampRange {
    /// <p>The starting timestamp in the range of timestamps for which to return fragments.</p>
    /// <p>Only fragments that start exactly at or after <code>StartTimestamp</code> are included in the session. Fragments that start before <code>StartTimestamp</code> and continue past it aren't included in the session. If <code>FragmentSelectorType</code> is <code>SERVER_TIMESTAMP</code>, the <code>StartTimestamp</code> must be later than the stream head.</p>
    pub start_timestamp: ::aws_smithy_types::DateTime,
    /// <p>The end of the timestamp range for the requested media.</p>
    /// <p>This value must be within 24 hours of the specified <code>StartTimestamp</code>, and it must be later than the <code>StartTimestamp</code> value. If <code>FragmentSelectorType</code> for the request is <code>SERVER_TIMESTAMP</code>, this value must be in the past.</p>
    /// <p>This value is inclusive. The <code>EndTimestamp</code> is compared to the (starting) timestamp of the fragment. Fragments that start before the <code>EndTimestamp</code> value and continue past it are included in the session.</p>
    pub end_timestamp: ::aws_smithy_types::DateTime,
}
impl ClipTimestampRange {
    /// <p>The starting timestamp in the range of timestamps for which to return fragments.</p>
    /// <p>Only fragments that start exactly at or after <code>StartTimestamp</code> are included in the session. Fragments that start before <code>StartTimestamp</code> and continue past it aren't included in the session. If <code>FragmentSelectorType</code> is <code>SERVER_TIMESTAMP</code>, the <code>StartTimestamp</code> must be later than the stream head.</p>
    pub fn start_timestamp(&self) -> &::aws_smithy_types::DateTime {
        &self.start_timestamp
    }
    /// <p>The end of the timestamp range for the requested media.</p>
    /// <p>This value must be within 24 hours of the specified <code>StartTimestamp</code>, and it must be later than the <code>StartTimestamp</code> value. If <code>FragmentSelectorType</code> for the request is <code>SERVER_TIMESTAMP</code>, this value must be in the past.</p>
    /// <p>This value is inclusive. The <code>EndTimestamp</code> is compared to the (starting) timestamp of the fragment. Fragments that start before the <code>EndTimestamp</code> value and continue past it are included in the session.</p>
    pub fn end_timestamp(&self) -> &::aws_smithy_types::DateTime {
        &self.end_timestamp
    }
}
impl ClipTimestampRange {
    /// Creates a new builder-style object to manufacture [`ClipTimestampRange`](crate::types::ClipTimestampRange).
    pub fn builder() -> crate::types::builders::ClipTimestampRangeBuilder {
        crate::types::builders::ClipTimestampRangeBuilder::default()
    }
}

/// A builder for [`ClipTimestampRange`](crate::types::ClipTimestampRange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClipTimestampRangeBuilder {
    pub(crate) start_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ClipTimestampRangeBuilder {
    /// <p>The starting timestamp in the range of timestamps for which to return fragments.</p>
    /// <p>Only fragments that start exactly at or after <code>StartTimestamp</code> are included in the session. Fragments that start before <code>StartTimestamp</code> and continue past it aren't included in the session. If <code>FragmentSelectorType</code> is <code>SERVER_TIMESTAMP</code>, the <code>StartTimestamp</code> must be later than the stream head.</p>
    /// This field is required.
    pub fn start_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The starting timestamp in the range of timestamps for which to return fragments.</p>
    /// <p>Only fragments that start exactly at or after <code>StartTimestamp</code> are included in the session. Fragments that start before <code>StartTimestamp</code> and continue past it aren't included in the session. If <code>FragmentSelectorType</code> is <code>SERVER_TIMESTAMP</code>, the <code>StartTimestamp</code> must be later than the stream head.</p>
    pub fn set_start_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_timestamp = input;
        self
    }
    /// <p>The starting timestamp in the range of timestamps for which to return fragments.</p>
    /// <p>Only fragments that start exactly at or after <code>StartTimestamp</code> are included in the session. Fragments that start before <code>StartTimestamp</code> and continue past it aren't included in the session. If <code>FragmentSelectorType</code> is <code>SERVER_TIMESTAMP</code>, the <code>StartTimestamp</code> must be later than the stream head.</p>
    pub fn get_start_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_timestamp
    }
    /// <p>The end of the timestamp range for the requested media.</p>
    /// <p>This value must be within 24 hours of the specified <code>StartTimestamp</code>, and it must be later than the <code>StartTimestamp</code> value. If <code>FragmentSelectorType</code> for the request is <code>SERVER_TIMESTAMP</code>, this value must be in the past.</p>
    /// <p>This value is inclusive. The <code>EndTimestamp</code> is compared to the (starting) timestamp of the fragment. Fragments that start before the <code>EndTimestamp</code> value and continue past it are included in the session.</p>
    /// This field is required.
    pub fn end_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end of the timestamp range for the requested media.</p>
    /// <p>This value must be within 24 hours of the specified <code>StartTimestamp</code>, and it must be later than the <code>StartTimestamp</code> value. If <code>FragmentSelectorType</code> for the request is <code>SERVER_TIMESTAMP</code>, this value must be in the past.</p>
    /// <p>This value is inclusive. The <code>EndTimestamp</code> is compared to the (starting) timestamp of the fragment. Fragments that start before the <code>EndTimestamp</code> value and continue past it are included in the session.</p>
    pub fn set_end_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_timestamp = input;
        self
    }
    /// <p>The end of the timestamp range for the requested media.</p>
    /// <p>This value must be within 24 hours of the specified <code>StartTimestamp</code>, and it must be later than the <code>StartTimestamp</code> value. If <code>FragmentSelectorType</code> for the request is <code>SERVER_TIMESTAMP</code>, this value must be in the past.</p>
    /// <p>This value is inclusive. The <code>EndTimestamp</code> is compared to the (starting) timestamp of the fragment. Fragments that start before the <code>EndTimestamp</code> value and continue past it are included in the session.</p>
    pub fn get_end_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_timestamp
    }
    /// Consumes the builder and constructs a [`ClipTimestampRange`](crate::types::ClipTimestampRange).
    /// This method will fail if any of the following fields are not set:
    /// - [`start_timestamp`](crate::types::builders::ClipTimestampRangeBuilder::start_timestamp)
    /// - [`end_timestamp`](crate::types::builders::ClipTimestampRangeBuilder::end_timestamp)
    pub fn build(self) -> ::std::result::Result<crate::types::ClipTimestampRange, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ClipTimestampRange {
            start_timestamp: self.start_timestamp.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "start_timestamp",
                    "start_timestamp was not specified but it is required when building ClipTimestampRange",
                )
            })?,
            end_timestamp: self.end_timestamp.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "end_timestamp",
                    "end_timestamp was not specified but it is required when building ClipTimestampRange",
                )
            })?,
        })
    }
}
