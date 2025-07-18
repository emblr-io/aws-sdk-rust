// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Channel mapping contains the group of fields that hold the remixing value for each channel, in dB. Specify remix values to indicate how much of the content from your input audio channel you want in your output audio channels. Each instance of the InputChannels or InputChannelsFineTune array specifies these values for one output channel. Use one instance of this array for each output channel. In the console, each array corresponds to a column in the graphical depiction of the mapping matrix. The rows of the graphical matrix correspond to input channels. Valid values are within the range from -60 (mute) through 6. A setting of 0 passes the input channel unchanged to the output channel (no attenuation or amplification). Use InputChannels or InputChannelsFineTune to specify your remix values. Don't use both.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChannelMapping {
    /// In your JSON job specification, include one child of OutputChannels for each audio channel that you want in your output. Each child should contain one instance of InputChannels or InputChannelsFineTune.
    pub output_channels: ::std::option::Option<::std::vec::Vec<crate::types::OutputChannelMapping>>,
}
impl ChannelMapping {
    /// In your JSON job specification, include one child of OutputChannels for each audio channel that you want in your output. Each child should contain one instance of InputChannels or InputChannelsFineTune.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.output_channels.is_none()`.
    pub fn output_channels(&self) -> &[crate::types::OutputChannelMapping] {
        self.output_channels.as_deref().unwrap_or_default()
    }
}
impl ChannelMapping {
    /// Creates a new builder-style object to manufacture [`ChannelMapping`](crate::types::ChannelMapping).
    pub fn builder() -> crate::types::builders::ChannelMappingBuilder {
        crate::types::builders::ChannelMappingBuilder::default()
    }
}

/// A builder for [`ChannelMapping`](crate::types::ChannelMapping).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChannelMappingBuilder {
    pub(crate) output_channels: ::std::option::Option<::std::vec::Vec<crate::types::OutputChannelMapping>>,
}
impl ChannelMappingBuilder {
    /// Appends an item to `output_channels`.
    ///
    /// To override the contents of this collection use [`set_output_channels`](Self::set_output_channels).
    ///
    /// In your JSON job specification, include one child of OutputChannels for each audio channel that you want in your output. Each child should contain one instance of InputChannels or InputChannelsFineTune.
    pub fn output_channels(mut self, input: crate::types::OutputChannelMapping) -> Self {
        let mut v = self.output_channels.unwrap_or_default();
        v.push(input);
        self.output_channels = ::std::option::Option::Some(v);
        self
    }
    /// In your JSON job specification, include one child of OutputChannels for each audio channel that you want in your output. Each child should contain one instance of InputChannels or InputChannelsFineTune.
    pub fn set_output_channels(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OutputChannelMapping>>) -> Self {
        self.output_channels = input;
        self
    }
    /// In your JSON job specification, include one child of OutputChannels for each audio channel that you want in your output. Each child should contain one instance of InputChannels or InputChannelsFineTune.
    pub fn get_output_channels(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OutputChannelMapping>> {
        &self.output_channels
    }
    /// Consumes the builder and constructs a [`ChannelMapping`](crate::types::ChannelMapping).
    pub fn build(self) -> crate::types::ChannelMapping {
        crate::types::ChannelMapping {
            output_channels: self.output_channels,
        }
    }
}
