// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Required when you set Codec to the value MP2.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Mp2Settings {
    /// Specify the average bitrate in bits per second.
    pub bitrate: ::std::option::Option<i32>,
    /// Set Channels to specify the number of channels in this output audio track. Choosing Mono in will give you 1 output channel; choosing Stereo will give you 2. In the API, valid values are 1 and 2.
    pub channels: ::std::option::Option<i32>,
    /// Sample rate in Hz.
    pub sample_rate: ::std::option::Option<i32>,
}
impl Mp2Settings {
    /// Specify the average bitrate in bits per second.
    pub fn bitrate(&self) -> ::std::option::Option<i32> {
        self.bitrate
    }
    /// Set Channels to specify the number of channels in this output audio track. Choosing Mono in will give you 1 output channel; choosing Stereo will give you 2. In the API, valid values are 1 and 2.
    pub fn channels(&self) -> ::std::option::Option<i32> {
        self.channels
    }
    /// Sample rate in Hz.
    pub fn sample_rate(&self) -> ::std::option::Option<i32> {
        self.sample_rate
    }
}
impl Mp2Settings {
    /// Creates a new builder-style object to manufacture [`Mp2Settings`](crate::types::Mp2Settings).
    pub fn builder() -> crate::types::builders::Mp2SettingsBuilder {
        crate::types::builders::Mp2SettingsBuilder::default()
    }
}

/// A builder for [`Mp2Settings`](crate::types::Mp2Settings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Mp2SettingsBuilder {
    pub(crate) bitrate: ::std::option::Option<i32>,
    pub(crate) channels: ::std::option::Option<i32>,
    pub(crate) sample_rate: ::std::option::Option<i32>,
}
impl Mp2SettingsBuilder {
    /// Specify the average bitrate in bits per second.
    pub fn bitrate(mut self, input: i32) -> Self {
        self.bitrate = ::std::option::Option::Some(input);
        self
    }
    /// Specify the average bitrate in bits per second.
    pub fn set_bitrate(mut self, input: ::std::option::Option<i32>) -> Self {
        self.bitrate = input;
        self
    }
    /// Specify the average bitrate in bits per second.
    pub fn get_bitrate(&self) -> &::std::option::Option<i32> {
        &self.bitrate
    }
    /// Set Channels to specify the number of channels in this output audio track. Choosing Mono in will give you 1 output channel; choosing Stereo will give you 2. In the API, valid values are 1 and 2.
    pub fn channels(mut self, input: i32) -> Self {
        self.channels = ::std::option::Option::Some(input);
        self
    }
    /// Set Channels to specify the number of channels in this output audio track. Choosing Mono in will give you 1 output channel; choosing Stereo will give you 2. In the API, valid values are 1 and 2.
    pub fn set_channels(mut self, input: ::std::option::Option<i32>) -> Self {
        self.channels = input;
        self
    }
    /// Set Channels to specify the number of channels in this output audio track. Choosing Mono in will give you 1 output channel; choosing Stereo will give you 2. In the API, valid values are 1 and 2.
    pub fn get_channels(&self) -> &::std::option::Option<i32> {
        &self.channels
    }
    /// Sample rate in Hz.
    pub fn sample_rate(mut self, input: i32) -> Self {
        self.sample_rate = ::std::option::Option::Some(input);
        self
    }
    /// Sample rate in Hz.
    pub fn set_sample_rate(mut self, input: ::std::option::Option<i32>) -> Self {
        self.sample_rate = input;
        self
    }
    /// Sample rate in Hz.
    pub fn get_sample_rate(&self) -> &::std::option::Option<i32> {
        &self.sample_rate
    }
    /// Consumes the builder and constructs a [`Mp2Settings`](crate::types::Mp2Settings).
    pub fn build(self) -> crate::types::Mp2Settings {
        crate::types::Mp2Settings {
            bitrate: self.bitrate,
            channels: self.channels,
            sample_rate: self.sample_rate,
        }
    }
}
