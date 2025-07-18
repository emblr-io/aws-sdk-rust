// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about which channels are supported, and how many contacts an agent can have on a channel simultaneously.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MediaConcurrency {
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    pub channel: crate::types::Channel,
    /// <p>The number of contacts an agent can have on a channel simultaneously.</p>
    /// <p>Valid Range for <code>VOICE</code>: Minimum value of 1. Maximum value of 1.</p>
    /// <p>Valid Range for <code>CHAT</code>: Minimum value of 1. Maximum value of 10.</p>
    /// <p>Valid Range for <code>TASK</code>: Minimum value of 1. Maximum value of 10.</p>
    pub concurrency: i32,
    /// <p>Defines the cross-channel routing behavior for each channel that is enabled for this Routing Profile. For example, this allows you to offer an agent a different contact from another channel when they are currently working with a contact from a Voice channel.</p>
    pub cross_channel_behavior: ::std::option::Option<crate::types::CrossChannelBehavior>,
}
impl MediaConcurrency {
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    pub fn channel(&self) -> &crate::types::Channel {
        &self.channel
    }
    /// <p>The number of contacts an agent can have on a channel simultaneously.</p>
    /// <p>Valid Range for <code>VOICE</code>: Minimum value of 1. Maximum value of 1.</p>
    /// <p>Valid Range for <code>CHAT</code>: Minimum value of 1. Maximum value of 10.</p>
    /// <p>Valid Range for <code>TASK</code>: Minimum value of 1. Maximum value of 10.</p>
    pub fn concurrency(&self) -> i32 {
        self.concurrency
    }
    /// <p>Defines the cross-channel routing behavior for each channel that is enabled for this Routing Profile. For example, this allows you to offer an agent a different contact from another channel when they are currently working with a contact from a Voice channel.</p>
    pub fn cross_channel_behavior(&self) -> ::std::option::Option<&crate::types::CrossChannelBehavior> {
        self.cross_channel_behavior.as_ref()
    }
}
impl MediaConcurrency {
    /// Creates a new builder-style object to manufacture [`MediaConcurrency`](crate::types::MediaConcurrency).
    pub fn builder() -> crate::types::builders::MediaConcurrencyBuilder {
        crate::types::builders::MediaConcurrencyBuilder::default()
    }
}

/// A builder for [`MediaConcurrency`](crate::types::MediaConcurrency).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MediaConcurrencyBuilder {
    pub(crate) channel: ::std::option::Option<crate::types::Channel>,
    pub(crate) concurrency: ::std::option::Option<i32>,
    pub(crate) cross_channel_behavior: ::std::option::Option<crate::types::CrossChannelBehavior>,
}
impl MediaConcurrencyBuilder {
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    /// This field is required.
    pub fn channel(mut self, input: crate::types::Channel) -> Self {
        self.channel = ::std::option::Option::Some(input);
        self
    }
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    pub fn set_channel(mut self, input: ::std::option::Option<crate::types::Channel>) -> Self {
        self.channel = input;
        self
    }
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    pub fn get_channel(&self) -> &::std::option::Option<crate::types::Channel> {
        &self.channel
    }
    /// <p>The number of contacts an agent can have on a channel simultaneously.</p>
    /// <p>Valid Range for <code>VOICE</code>: Minimum value of 1. Maximum value of 1.</p>
    /// <p>Valid Range for <code>CHAT</code>: Minimum value of 1. Maximum value of 10.</p>
    /// <p>Valid Range for <code>TASK</code>: Minimum value of 1. Maximum value of 10.</p>
    /// This field is required.
    pub fn concurrency(mut self, input: i32) -> Self {
        self.concurrency = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of contacts an agent can have on a channel simultaneously.</p>
    /// <p>Valid Range for <code>VOICE</code>: Minimum value of 1. Maximum value of 1.</p>
    /// <p>Valid Range for <code>CHAT</code>: Minimum value of 1. Maximum value of 10.</p>
    /// <p>Valid Range for <code>TASK</code>: Minimum value of 1. Maximum value of 10.</p>
    pub fn set_concurrency(mut self, input: ::std::option::Option<i32>) -> Self {
        self.concurrency = input;
        self
    }
    /// <p>The number of contacts an agent can have on a channel simultaneously.</p>
    /// <p>Valid Range for <code>VOICE</code>: Minimum value of 1. Maximum value of 1.</p>
    /// <p>Valid Range for <code>CHAT</code>: Minimum value of 1. Maximum value of 10.</p>
    /// <p>Valid Range for <code>TASK</code>: Minimum value of 1. Maximum value of 10.</p>
    pub fn get_concurrency(&self) -> &::std::option::Option<i32> {
        &self.concurrency
    }
    /// <p>Defines the cross-channel routing behavior for each channel that is enabled for this Routing Profile. For example, this allows you to offer an agent a different contact from another channel when they are currently working with a contact from a Voice channel.</p>
    pub fn cross_channel_behavior(mut self, input: crate::types::CrossChannelBehavior) -> Self {
        self.cross_channel_behavior = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the cross-channel routing behavior for each channel that is enabled for this Routing Profile. For example, this allows you to offer an agent a different contact from another channel when they are currently working with a contact from a Voice channel.</p>
    pub fn set_cross_channel_behavior(mut self, input: ::std::option::Option<crate::types::CrossChannelBehavior>) -> Self {
        self.cross_channel_behavior = input;
        self
    }
    /// <p>Defines the cross-channel routing behavior for each channel that is enabled for this Routing Profile. For example, this allows you to offer an agent a different contact from another channel when they are currently working with a contact from a Voice channel.</p>
    pub fn get_cross_channel_behavior(&self) -> &::std::option::Option<crate::types::CrossChannelBehavior> {
        &self.cross_channel_behavior
    }
    /// Consumes the builder and constructs a [`MediaConcurrency`](crate::types::MediaConcurrency).
    /// This method will fail if any of the following fields are not set:
    /// - [`channel`](crate::types::builders::MediaConcurrencyBuilder::channel)
    /// - [`concurrency`](crate::types::builders::MediaConcurrencyBuilder::concurrency)
    pub fn build(self) -> ::std::result::Result<crate::types::MediaConcurrency, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MediaConcurrency {
            channel: self.channel.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "channel",
                    "channel was not specified but it is required when building MediaConcurrency",
                )
            })?,
            concurrency: self.concurrency.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "concurrency",
                    "concurrency was not specified but it is required when building MediaConcurrency",
                )
            })?,
            cross_channel_behavior: self.cross_channel_behavior,
        })
    }
}
