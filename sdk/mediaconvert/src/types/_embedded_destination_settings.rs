// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Settings related to CEA/EIA-608 and CEA/EIA-708 (also called embedded or ancillary) captions. Set up embedded captions in the same output as your video. For more information, see https://docs.aws.amazon.com/mediaconvert/latest/ug/embedded-output-captions.html.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EmbeddedDestinationSettings {
    /// Ignore this setting unless your input captions are SCC format and your output captions are embedded in the video stream. Specify a CC number for each captions channel in this output. If you have two channels, choose CC numbers that aren't in the same field. For example, choose 1 and 3. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub destination608_channel_number: ::std::option::Option<i32>,
    /// Ignore this setting unless your input captions are SCC format and you want both 608 and 708 captions embedded in your output stream. Optionally, specify the 708 service number for each output captions channel. Choose a different number for each channel. To use this setting, also set Force 608 to 708 upconvert to Upconvert in your input captions selector settings. If you choose to upconvert but don't specify a 708 service number, MediaConvert uses the number that you specify for CC channel number for the 708 service number. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub destination708_service_number: ::std::option::Option<i32>,
}
impl EmbeddedDestinationSettings {
    /// Ignore this setting unless your input captions are SCC format and your output captions are embedded in the video stream. Specify a CC number for each captions channel in this output. If you have two channels, choose CC numbers that aren't in the same field. For example, choose 1 and 3. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub fn destination608_channel_number(&self) -> ::std::option::Option<i32> {
        self.destination608_channel_number
    }
    /// Ignore this setting unless your input captions are SCC format and you want both 608 and 708 captions embedded in your output stream. Optionally, specify the 708 service number for each output captions channel. Choose a different number for each channel. To use this setting, also set Force 608 to 708 upconvert to Upconvert in your input captions selector settings. If you choose to upconvert but don't specify a 708 service number, MediaConvert uses the number that you specify for CC channel number for the 708 service number. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub fn destination708_service_number(&self) -> ::std::option::Option<i32> {
        self.destination708_service_number
    }
}
impl EmbeddedDestinationSettings {
    /// Creates a new builder-style object to manufacture [`EmbeddedDestinationSettings`](crate::types::EmbeddedDestinationSettings).
    pub fn builder() -> crate::types::builders::EmbeddedDestinationSettingsBuilder {
        crate::types::builders::EmbeddedDestinationSettingsBuilder::default()
    }
}

/// A builder for [`EmbeddedDestinationSettings`](crate::types::EmbeddedDestinationSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EmbeddedDestinationSettingsBuilder {
    pub(crate) destination608_channel_number: ::std::option::Option<i32>,
    pub(crate) destination708_service_number: ::std::option::Option<i32>,
}
impl EmbeddedDestinationSettingsBuilder {
    /// Ignore this setting unless your input captions are SCC format and your output captions are embedded in the video stream. Specify a CC number for each captions channel in this output. If you have two channels, choose CC numbers that aren't in the same field. For example, choose 1 and 3. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub fn destination608_channel_number(mut self, input: i32) -> Self {
        self.destination608_channel_number = ::std::option::Option::Some(input);
        self
    }
    /// Ignore this setting unless your input captions are SCC format and your output captions are embedded in the video stream. Specify a CC number for each captions channel in this output. If you have two channels, choose CC numbers that aren't in the same field. For example, choose 1 and 3. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub fn set_destination608_channel_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.destination608_channel_number = input;
        self
    }
    /// Ignore this setting unless your input captions are SCC format and your output captions are embedded in the video stream. Specify a CC number for each captions channel in this output. If you have two channels, choose CC numbers that aren't in the same field. For example, choose 1 and 3. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub fn get_destination608_channel_number(&self) -> &::std::option::Option<i32> {
        &self.destination608_channel_number
    }
    /// Ignore this setting unless your input captions are SCC format and you want both 608 and 708 captions embedded in your output stream. Optionally, specify the 708 service number for each output captions channel. Choose a different number for each channel. To use this setting, also set Force 608 to 708 upconvert to Upconvert in your input captions selector settings. If you choose to upconvert but don't specify a 708 service number, MediaConvert uses the number that you specify for CC channel number for the 708 service number. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub fn destination708_service_number(mut self, input: i32) -> Self {
        self.destination708_service_number = ::std::option::Option::Some(input);
        self
    }
    /// Ignore this setting unless your input captions are SCC format and you want both 608 and 708 captions embedded in your output stream. Optionally, specify the 708 service number for each output captions channel. Choose a different number for each channel. To use this setting, also set Force 608 to 708 upconvert to Upconvert in your input captions selector settings. If you choose to upconvert but don't specify a 708 service number, MediaConvert uses the number that you specify for CC channel number for the 708 service number. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub fn set_destination708_service_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.destination708_service_number = input;
        self
    }
    /// Ignore this setting unless your input captions are SCC format and you want both 608 and 708 captions embedded in your output stream. Optionally, specify the 708 service number for each output captions channel. Choose a different number for each channel. To use this setting, also set Force 608 to 708 upconvert to Upconvert in your input captions selector settings. If you choose to upconvert but don't specify a 708 service number, MediaConvert uses the number that you specify for CC channel number for the 708 service number. For more information, see https://docs.aws.amazon.com/console/mediaconvert/dual-scc-to-embedded.
    pub fn get_destination708_service_number(&self) -> &::std::option::Option<i32> {
        &self.destination708_service_number
    }
    /// Consumes the builder and constructs a [`EmbeddedDestinationSettings`](crate::types::EmbeddedDestinationSettings).
    pub fn build(self) -> crate::types::EmbeddedDestinationSettings {
        crate::types::EmbeddedDestinationSettings {
            destination608_channel_number: self.destination608_channel_number,
            destination708_service_number: self.destination708_service_number,
        }
    }
}
