// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Channel class that the channel should be updated to.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateChannelClassInput {
    /// The channel class that you wish to update this channel to use.
    pub channel_class: ::std::option::Option<crate::types::ChannelClass>,
    /// Channel Id of the channel whose class should be updated.
    pub channel_id: ::std::option::Option<::std::string::String>,
    /// A list of output destinations for this channel.
    pub destinations: ::std::option::Option<::std::vec::Vec<crate::types::OutputDestination>>,
}
impl UpdateChannelClassInput {
    /// The channel class that you wish to update this channel to use.
    pub fn channel_class(&self) -> ::std::option::Option<&crate::types::ChannelClass> {
        self.channel_class.as_ref()
    }
    /// Channel Id of the channel whose class should be updated.
    pub fn channel_id(&self) -> ::std::option::Option<&str> {
        self.channel_id.as_deref()
    }
    /// A list of output destinations for this channel.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.destinations.is_none()`.
    pub fn destinations(&self) -> &[crate::types::OutputDestination] {
        self.destinations.as_deref().unwrap_or_default()
    }
}
impl UpdateChannelClassInput {
    /// Creates a new builder-style object to manufacture [`UpdateChannelClassInput`](crate::operation::update_channel_class::UpdateChannelClassInput).
    pub fn builder() -> crate::operation::update_channel_class::builders::UpdateChannelClassInputBuilder {
        crate::operation::update_channel_class::builders::UpdateChannelClassInputBuilder::default()
    }
}

/// A builder for [`UpdateChannelClassInput`](crate::operation::update_channel_class::UpdateChannelClassInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateChannelClassInputBuilder {
    pub(crate) channel_class: ::std::option::Option<crate::types::ChannelClass>,
    pub(crate) channel_id: ::std::option::Option<::std::string::String>,
    pub(crate) destinations: ::std::option::Option<::std::vec::Vec<crate::types::OutputDestination>>,
}
impl UpdateChannelClassInputBuilder {
    /// The channel class that you wish to update this channel to use.
    /// This field is required.
    pub fn channel_class(mut self, input: crate::types::ChannelClass) -> Self {
        self.channel_class = ::std::option::Option::Some(input);
        self
    }
    /// The channel class that you wish to update this channel to use.
    pub fn set_channel_class(mut self, input: ::std::option::Option<crate::types::ChannelClass>) -> Self {
        self.channel_class = input;
        self
    }
    /// The channel class that you wish to update this channel to use.
    pub fn get_channel_class(&self) -> &::std::option::Option<crate::types::ChannelClass> {
        &self.channel_class
    }
    /// Channel Id of the channel whose class should be updated.
    /// This field is required.
    pub fn channel_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_id = ::std::option::Option::Some(input.into());
        self
    }
    /// Channel Id of the channel whose class should be updated.
    pub fn set_channel_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_id = input;
        self
    }
    /// Channel Id of the channel whose class should be updated.
    pub fn get_channel_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_id
    }
    /// Appends an item to `destinations`.
    ///
    /// To override the contents of this collection use [`set_destinations`](Self::set_destinations).
    ///
    /// A list of output destinations for this channel.
    pub fn destinations(mut self, input: crate::types::OutputDestination) -> Self {
        let mut v = self.destinations.unwrap_or_default();
        v.push(input);
        self.destinations = ::std::option::Option::Some(v);
        self
    }
    /// A list of output destinations for this channel.
    pub fn set_destinations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OutputDestination>>) -> Self {
        self.destinations = input;
        self
    }
    /// A list of output destinations for this channel.
    pub fn get_destinations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OutputDestination>> {
        &self.destinations
    }
    /// Consumes the builder and constructs a [`UpdateChannelClassInput`](crate::operation::update_channel_class::UpdateChannelClassInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_channel_class::UpdateChannelClassInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_channel_class::UpdateChannelClassInput {
            channel_class: self.channel_class,
            channel_id: self.channel_id,
            destinations: self.destinations,
        })
    }
}
