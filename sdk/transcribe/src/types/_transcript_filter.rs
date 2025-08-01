// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Flag the presence or absence of specific words or phrases detected in your Call Analytics transcription output.</p>
/// <p>Rules using <code>TranscriptFilter</code> are designed to match:</p>
/// <ul>
/// <li>
/// <p>Custom words or phrases spoken by the agent, the customer, or both</p></li>
/// <li>
/// <p>Custom words or phrases <b>not</b> spoken by the agent, the customer, or either</p></li>
/// <li>
/// <p>Custom words or phrases that occur at a specific time frame</p></li>
/// </ul>
/// <p>See <a href="https://docs.aws.amazon.com/transcribe/latest/dg/tca-categories-batch.html#tca-rules-batch">Rule criteria for post-call categories</a> and <a href="https://docs.aws.amazon.com/transcribe/latest/dg/tca-categories-stream.html#tca-rules-stream">Rule criteria for streaming categories</a> for usage examples.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TranscriptFilter {
    /// <p>Flag the presence or absence of an exact match to the phrases that you specify. For example, if you specify the phrase "speak to a manager" as your <code>Targets</code> value, only that exact phrase is flagged.</p>
    /// <p>Note that semantic matching is not supported. For example, if your customer says "speak to <i>the</i> manager", instead of "speak to <i>a</i> manager", your content is not flagged.</p>
    pub transcript_filter_type: crate::types::TranscriptFilterType,
    /// <p>Makes it possible to specify a time range (in milliseconds) in your audio, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub absolute_time_range: ::std::option::Option<crate::types::AbsoluteTimeRange>,
    /// <p>Makes it possible to specify a time range (in percentage) in your media file, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub relative_time_range: ::std::option::Option<crate::types::RelativeTimeRange>,
    /// <p>Specify the participant that you want to flag. Omitting this parameter is equivalent to specifying both participants.</p>
    pub participant_role: ::std::option::Option<crate::types::ParticipantRole>,
    /// <p>Set to <code>TRUE</code> to flag the absence of the phrase that you specified in your request. Set to <code>FALSE</code> to flag the presence of the phrase that you specified in your request.</p>
    pub negate: ::std::option::Option<bool>,
    /// <p>Specify the phrases that you want to flag.</p>
    pub targets: ::std::vec::Vec<::std::string::String>,
}
impl TranscriptFilter {
    /// <p>Flag the presence or absence of an exact match to the phrases that you specify. For example, if you specify the phrase "speak to a manager" as your <code>Targets</code> value, only that exact phrase is flagged.</p>
    /// <p>Note that semantic matching is not supported. For example, if your customer says "speak to <i>the</i> manager", instead of "speak to <i>a</i> manager", your content is not flagged.</p>
    pub fn transcript_filter_type(&self) -> &crate::types::TranscriptFilterType {
        &self.transcript_filter_type
    }
    /// <p>Makes it possible to specify a time range (in milliseconds) in your audio, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub fn absolute_time_range(&self) -> ::std::option::Option<&crate::types::AbsoluteTimeRange> {
        self.absolute_time_range.as_ref()
    }
    /// <p>Makes it possible to specify a time range (in percentage) in your media file, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub fn relative_time_range(&self) -> ::std::option::Option<&crate::types::RelativeTimeRange> {
        self.relative_time_range.as_ref()
    }
    /// <p>Specify the participant that you want to flag. Omitting this parameter is equivalent to specifying both participants.</p>
    pub fn participant_role(&self) -> ::std::option::Option<&crate::types::ParticipantRole> {
        self.participant_role.as_ref()
    }
    /// <p>Set to <code>TRUE</code> to flag the absence of the phrase that you specified in your request. Set to <code>FALSE</code> to flag the presence of the phrase that you specified in your request.</p>
    pub fn negate(&self) -> ::std::option::Option<bool> {
        self.negate
    }
    /// <p>Specify the phrases that you want to flag.</p>
    pub fn targets(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.targets.deref()
    }
}
impl TranscriptFilter {
    /// Creates a new builder-style object to manufacture [`TranscriptFilter`](crate::types::TranscriptFilter).
    pub fn builder() -> crate::types::builders::TranscriptFilterBuilder {
        crate::types::builders::TranscriptFilterBuilder::default()
    }
}

/// A builder for [`TranscriptFilter`](crate::types::TranscriptFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TranscriptFilterBuilder {
    pub(crate) transcript_filter_type: ::std::option::Option<crate::types::TranscriptFilterType>,
    pub(crate) absolute_time_range: ::std::option::Option<crate::types::AbsoluteTimeRange>,
    pub(crate) relative_time_range: ::std::option::Option<crate::types::RelativeTimeRange>,
    pub(crate) participant_role: ::std::option::Option<crate::types::ParticipantRole>,
    pub(crate) negate: ::std::option::Option<bool>,
    pub(crate) targets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TranscriptFilterBuilder {
    /// <p>Flag the presence or absence of an exact match to the phrases that you specify. For example, if you specify the phrase "speak to a manager" as your <code>Targets</code> value, only that exact phrase is flagged.</p>
    /// <p>Note that semantic matching is not supported. For example, if your customer says "speak to <i>the</i> manager", instead of "speak to <i>a</i> manager", your content is not flagged.</p>
    /// This field is required.
    pub fn transcript_filter_type(mut self, input: crate::types::TranscriptFilterType) -> Self {
        self.transcript_filter_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Flag the presence or absence of an exact match to the phrases that you specify. For example, if you specify the phrase "speak to a manager" as your <code>Targets</code> value, only that exact phrase is flagged.</p>
    /// <p>Note that semantic matching is not supported. For example, if your customer says "speak to <i>the</i> manager", instead of "speak to <i>a</i> manager", your content is not flagged.</p>
    pub fn set_transcript_filter_type(mut self, input: ::std::option::Option<crate::types::TranscriptFilterType>) -> Self {
        self.transcript_filter_type = input;
        self
    }
    /// <p>Flag the presence or absence of an exact match to the phrases that you specify. For example, if you specify the phrase "speak to a manager" as your <code>Targets</code> value, only that exact phrase is flagged.</p>
    /// <p>Note that semantic matching is not supported. For example, if your customer says "speak to <i>the</i> manager", instead of "speak to <i>a</i> manager", your content is not flagged.</p>
    pub fn get_transcript_filter_type(&self) -> &::std::option::Option<crate::types::TranscriptFilterType> {
        &self.transcript_filter_type
    }
    /// <p>Makes it possible to specify a time range (in milliseconds) in your audio, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub fn absolute_time_range(mut self, input: crate::types::AbsoluteTimeRange) -> Self {
        self.absolute_time_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>Makes it possible to specify a time range (in milliseconds) in your audio, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub fn set_absolute_time_range(mut self, input: ::std::option::Option<crate::types::AbsoluteTimeRange>) -> Self {
        self.absolute_time_range = input;
        self
    }
    /// <p>Makes it possible to specify a time range (in milliseconds) in your audio, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub fn get_absolute_time_range(&self) -> &::std::option::Option<crate::types::AbsoluteTimeRange> {
        &self.absolute_time_range
    }
    /// <p>Makes it possible to specify a time range (in percentage) in your media file, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub fn relative_time_range(mut self, input: crate::types::RelativeTimeRange) -> Self {
        self.relative_time_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>Makes it possible to specify a time range (in percentage) in your media file, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub fn set_relative_time_range(mut self, input: ::std::option::Option<crate::types::RelativeTimeRange>) -> Self {
        self.relative_time_range = input;
        self
    }
    /// <p>Makes it possible to specify a time range (in percentage) in your media file, during which you want to search for the specified key words or phrases. See for more detail.</p>
    pub fn get_relative_time_range(&self) -> &::std::option::Option<crate::types::RelativeTimeRange> {
        &self.relative_time_range
    }
    /// <p>Specify the participant that you want to flag. Omitting this parameter is equivalent to specifying both participants.</p>
    pub fn participant_role(mut self, input: crate::types::ParticipantRole) -> Self {
        self.participant_role = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify the participant that you want to flag. Omitting this parameter is equivalent to specifying both participants.</p>
    pub fn set_participant_role(mut self, input: ::std::option::Option<crate::types::ParticipantRole>) -> Self {
        self.participant_role = input;
        self
    }
    /// <p>Specify the participant that you want to flag. Omitting this parameter is equivalent to specifying both participants.</p>
    pub fn get_participant_role(&self) -> &::std::option::Option<crate::types::ParticipantRole> {
        &self.participant_role
    }
    /// <p>Set to <code>TRUE</code> to flag the absence of the phrase that you specified in your request. Set to <code>FALSE</code> to flag the presence of the phrase that you specified in your request.</p>
    pub fn negate(mut self, input: bool) -> Self {
        self.negate = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set to <code>TRUE</code> to flag the absence of the phrase that you specified in your request. Set to <code>FALSE</code> to flag the presence of the phrase that you specified in your request.</p>
    pub fn set_negate(mut self, input: ::std::option::Option<bool>) -> Self {
        self.negate = input;
        self
    }
    /// <p>Set to <code>TRUE</code> to flag the absence of the phrase that you specified in your request. Set to <code>FALSE</code> to flag the presence of the phrase that you specified in your request.</p>
    pub fn get_negate(&self) -> &::std::option::Option<bool> {
        &self.negate
    }
    /// Appends an item to `targets`.
    ///
    /// To override the contents of this collection use [`set_targets`](Self::set_targets).
    ///
    /// <p>Specify the phrases that you want to flag.</p>
    pub fn targets(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.targets.unwrap_or_default();
        v.push(input.into());
        self.targets = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specify the phrases that you want to flag.</p>
    pub fn set_targets(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.targets = input;
        self
    }
    /// <p>Specify the phrases that you want to flag.</p>
    pub fn get_targets(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.targets
    }
    /// Consumes the builder and constructs a [`TranscriptFilter`](crate::types::TranscriptFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`transcript_filter_type`](crate::types::builders::TranscriptFilterBuilder::transcript_filter_type)
    /// - [`targets`](crate::types::builders::TranscriptFilterBuilder::targets)
    pub fn build(self) -> ::std::result::Result<crate::types::TranscriptFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TranscriptFilter {
            transcript_filter_type: self.transcript_filter_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "transcript_filter_type",
                    "transcript_filter_type was not specified but it is required when building TranscriptFilter",
                )
            })?,
            absolute_time_range: self.absolute_time_range,
            relative_time_range: self.relative_time_range,
            participant_role: self.participant_role,
            negate: self.negate,
            targets: self.targets.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "targets",
                    "targets was not specified but it is required when building TranscriptFilter",
                )
            })?,
        })
    }
}
