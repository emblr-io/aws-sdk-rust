// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration parameters for a channel. For information about MediaTailor channels, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/channel-assembly-channels.html">Working with channels</a> in the <i>MediaTailor User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Channel {
    /// <p>The ARN of the channel.</p>
    pub arn: ::std::string::String,
    /// <p>The name of the channel.</p>
    pub channel_name: ::std::string::String,
    /// <p>Returns the state whether the channel is running or not.</p>
    pub channel_state: ::std::string::String,
    /// <p>The timestamp of when the channel was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The slate used to fill gaps between programs in the schedule. You must configure filler slate if your channel uses the <code>LINEAR</code> <code>PlaybackMode</code>. MediaTailor doesn't support filler slate for channels using the <code>LOOP</code> <code>PlaybackMode</code>.</p>
    pub filler_slate: ::std::option::Option<crate::types::SlateSource>,
    /// <p>The timestamp of when the channel was last modified.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The channel's output properties.</p>
    pub outputs: ::std::vec::Vec<crate::types::ResponseOutputItem>,
    /// <p>The type of playback mode for this channel.</p>
    /// <p><code>LINEAR</code> - Programs play back-to-back only once.</p>
    /// <p><code>LOOP</code> - Programs play back-to-back in an endless loop. When the last program in the schedule plays, playback loops back to the first program in the schedule.</p>
    pub playback_mode: ::std::string::String,
    /// <p>The tags to assign to the channel. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The tier for this channel. STANDARD tier channels can contain live programs.</p>
    pub tier: ::std::string::String,
    /// <p>The log configuration.</p>
    pub log_configuration: ::std::option::Option<crate::types::LogConfigurationForChannel>,
    /// <p>The list of audiences defined in channel.</p>
    pub audiences: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl Channel {
    /// <p>The ARN of the channel.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The name of the channel.</p>
    pub fn channel_name(&self) -> &str {
        use std::ops::Deref;
        self.channel_name.deref()
    }
    /// <p>Returns the state whether the channel is running or not.</p>
    pub fn channel_state(&self) -> &str {
        use std::ops::Deref;
        self.channel_state.deref()
    }
    /// <p>The timestamp of when the channel was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The slate used to fill gaps between programs in the schedule. You must configure filler slate if your channel uses the <code>LINEAR</code> <code>PlaybackMode</code>. MediaTailor doesn't support filler slate for channels using the <code>LOOP</code> <code>PlaybackMode</code>.</p>
    pub fn filler_slate(&self) -> ::std::option::Option<&crate::types::SlateSource> {
        self.filler_slate.as_ref()
    }
    /// <p>The timestamp of when the channel was last modified.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>The channel's output properties.</p>
    pub fn outputs(&self) -> &[crate::types::ResponseOutputItem] {
        use std::ops::Deref;
        self.outputs.deref()
    }
    /// <p>The type of playback mode for this channel.</p>
    /// <p><code>LINEAR</code> - Programs play back-to-back only once.</p>
    /// <p><code>LOOP</code> - Programs play back-to-back in an endless loop. When the last program in the schedule plays, playback loops back to the first program in the schedule.</p>
    pub fn playback_mode(&self) -> &str {
        use std::ops::Deref;
        self.playback_mode.deref()
    }
    /// <p>The tags to assign to the channel. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The tier for this channel. STANDARD tier channels can contain live programs.</p>
    pub fn tier(&self) -> &str {
        use std::ops::Deref;
        self.tier.deref()
    }
    /// <p>The log configuration.</p>
    pub fn log_configuration(&self) -> ::std::option::Option<&crate::types::LogConfigurationForChannel> {
        self.log_configuration.as_ref()
    }
    /// <p>The list of audiences defined in channel.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.audiences.is_none()`.
    pub fn audiences(&self) -> &[::std::string::String] {
        self.audiences.as_deref().unwrap_or_default()
    }
}
impl Channel {
    /// Creates a new builder-style object to manufacture [`Channel`](crate::types::Channel).
    pub fn builder() -> crate::types::builders::ChannelBuilder {
        crate::types::builders::ChannelBuilder::default()
    }
}

/// A builder for [`Channel`](crate::types::Channel).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChannelBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) channel_name: ::std::option::Option<::std::string::String>,
    pub(crate) channel_state: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) filler_slate: ::std::option::Option<crate::types::SlateSource>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) outputs: ::std::option::Option<::std::vec::Vec<crate::types::ResponseOutputItem>>,
    pub(crate) playback_mode: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) tier: ::std::option::Option<::std::string::String>,
    pub(crate) log_configuration: ::std::option::Option<crate::types::LogConfigurationForChannel>,
    pub(crate) audiences: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ChannelBuilder {
    /// <p>The ARN of the channel.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the channel.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the channel.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the channel.</p>
    /// This field is required.
    pub fn channel_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the channel.</p>
    pub fn set_channel_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_name = input;
        self
    }
    /// <p>The name of the channel.</p>
    pub fn get_channel_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_name
    }
    /// <p>Returns the state whether the channel is running or not.</p>
    /// This field is required.
    pub fn channel_state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the state whether the channel is running or not.</p>
    pub fn set_channel_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_state = input;
        self
    }
    /// <p>Returns the state whether the channel is running or not.</p>
    pub fn get_channel_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_state
    }
    /// <p>The timestamp of when the channel was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the channel was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The timestamp of when the channel was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The slate used to fill gaps between programs in the schedule. You must configure filler slate if your channel uses the <code>LINEAR</code> <code>PlaybackMode</code>. MediaTailor doesn't support filler slate for channels using the <code>LOOP</code> <code>PlaybackMode</code>.</p>
    pub fn filler_slate(mut self, input: crate::types::SlateSource) -> Self {
        self.filler_slate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The slate used to fill gaps between programs in the schedule. You must configure filler slate if your channel uses the <code>LINEAR</code> <code>PlaybackMode</code>. MediaTailor doesn't support filler slate for channels using the <code>LOOP</code> <code>PlaybackMode</code>.</p>
    pub fn set_filler_slate(mut self, input: ::std::option::Option<crate::types::SlateSource>) -> Self {
        self.filler_slate = input;
        self
    }
    /// <p>The slate used to fill gaps between programs in the schedule. You must configure filler slate if your channel uses the <code>LINEAR</code> <code>PlaybackMode</code>. MediaTailor doesn't support filler slate for channels using the <code>LOOP</code> <code>PlaybackMode</code>.</p>
    pub fn get_filler_slate(&self) -> &::std::option::Option<crate::types::SlateSource> {
        &self.filler_slate
    }
    /// <p>The timestamp of when the channel was last modified.</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the channel was last modified.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The timestamp of when the channel was last modified.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// Appends an item to `outputs`.
    ///
    /// To override the contents of this collection use [`set_outputs`](Self::set_outputs).
    ///
    /// <p>The channel's output properties.</p>
    pub fn outputs(mut self, input: crate::types::ResponseOutputItem) -> Self {
        let mut v = self.outputs.unwrap_or_default();
        v.push(input);
        self.outputs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The channel's output properties.</p>
    pub fn set_outputs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResponseOutputItem>>) -> Self {
        self.outputs = input;
        self
    }
    /// <p>The channel's output properties.</p>
    pub fn get_outputs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResponseOutputItem>> {
        &self.outputs
    }
    /// <p>The type of playback mode for this channel.</p>
    /// <p><code>LINEAR</code> - Programs play back-to-back only once.</p>
    /// <p><code>LOOP</code> - Programs play back-to-back in an endless loop. When the last program in the schedule plays, playback loops back to the first program in the schedule.</p>
    /// This field is required.
    pub fn playback_mode(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.playback_mode = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of playback mode for this channel.</p>
    /// <p><code>LINEAR</code> - Programs play back-to-back only once.</p>
    /// <p><code>LOOP</code> - Programs play back-to-back in an endless loop. When the last program in the schedule plays, playback loops back to the first program in the schedule.</p>
    pub fn set_playback_mode(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.playback_mode = input;
        self
    }
    /// <p>The type of playback mode for this channel.</p>
    /// <p><code>LINEAR</code> - Programs play back-to-back only once.</p>
    /// <p><code>LOOP</code> - Programs play back-to-back in an endless loop. When the last program in the schedule plays, playback loops back to the first program in the schedule.</p>
    pub fn get_playback_mode(&self) -> &::std::option::Option<::std::string::String> {
        &self.playback_mode
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to assign to the channel. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags to assign to the channel. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to assign to the channel. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The tier for this channel. STANDARD tier channels can contain live programs.</p>
    /// This field is required.
    pub fn tier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The tier for this channel. STANDARD tier channels can contain live programs.</p>
    pub fn set_tier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tier = input;
        self
    }
    /// <p>The tier for this channel. STANDARD tier channels can contain live programs.</p>
    pub fn get_tier(&self) -> &::std::option::Option<::std::string::String> {
        &self.tier
    }
    /// <p>The log configuration.</p>
    /// This field is required.
    pub fn log_configuration(mut self, input: crate::types::LogConfigurationForChannel) -> Self {
        self.log_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The log configuration.</p>
    pub fn set_log_configuration(mut self, input: ::std::option::Option<crate::types::LogConfigurationForChannel>) -> Self {
        self.log_configuration = input;
        self
    }
    /// <p>The log configuration.</p>
    pub fn get_log_configuration(&self) -> &::std::option::Option<crate::types::LogConfigurationForChannel> {
        &self.log_configuration
    }
    /// Appends an item to `audiences`.
    ///
    /// To override the contents of this collection use [`set_audiences`](Self::set_audiences).
    ///
    /// <p>The list of audiences defined in channel.</p>
    pub fn audiences(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.audiences.unwrap_or_default();
        v.push(input.into());
        self.audiences = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of audiences defined in channel.</p>
    pub fn set_audiences(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.audiences = input;
        self
    }
    /// <p>The list of audiences defined in channel.</p>
    pub fn get_audiences(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.audiences
    }
    /// Consumes the builder and constructs a [`Channel`](crate::types::Channel).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::ChannelBuilder::arn)
    /// - [`channel_name`](crate::types::builders::ChannelBuilder::channel_name)
    /// - [`channel_state`](crate::types::builders::ChannelBuilder::channel_state)
    /// - [`outputs`](crate::types::builders::ChannelBuilder::outputs)
    /// - [`playback_mode`](crate::types::builders::ChannelBuilder::playback_mode)
    /// - [`tier`](crate::types::builders::ChannelBuilder::tier)
    pub fn build(self) -> ::std::result::Result<crate::types::Channel, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Channel {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building Channel",
                )
            })?,
            channel_name: self.channel_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "channel_name",
                    "channel_name was not specified but it is required when building Channel",
                )
            })?,
            channel_state: self.channel_state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "channel_state",
                    "channel_state was not specified but it is required when building Channel",
                )
            })?,
            creation_time: self.creation_time,
            filler_slate: self.filler_slate,
            last_modified_time: self.last_modified_time,
            outputs: self.outputs.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "outputs",
                    "outputs was not specified but it is required when building Channel",
                )
            })?,
            playback_mode: self.playback_mode.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "playback_mode",
                    "playback_mode was not specified but it is required when building Channel",
                )
            })?,
            tags: self.tags,
            tier: self.tier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "tier",
                    "tier was not specified but it is required when building Channel",
                )
            })?,
            log_configuration: self.log_configuration,
            audiences: self.audiences,
        })
    }
}
