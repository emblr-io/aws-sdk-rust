// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The attributes required to configure and create an elastic channel. An elastic channel can support a maximum of 1-million members.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ElasticChannelConfiguration {
    /// <p>The maximum number of SubChannels that you want to allow in the elastic channel.</p>
    pub maximum_sub_channels: i32,
    /// <p>The maximum number of members allowed in a SubChannel.</p>
    pub target_memberships_per_sub_channel: i32,
    /// <p>The minimum allowed percentage of TargetMembershipsPerSubChannel users. Ceil of the calculated value is used in balancing members among SubChannels of the elastic channel.</p>
    pub minimum_membership_percentage: i32,
}
impl ElasticChannelConfiguration {
    /// <p>The maximum number of SubChannels that you want to allow in the elastic channel.</p>
    pub fn maximum_sub_channels(&self) -> i32 {
        self.maximum_sub_channels
    }
    /// <p>The maximum number of members allowed in a SubChannel.</p>
    pub fn target_memberships_per_sub_channel(&self) -> i32 {
        self.target_memberships_per_sub_channel
    }
    /// <p>The minimum allowed percentage of TargetMembershipsPerSubChannel users. Ceil of the calculated value is used in balancing members among SubChannels of the elastic channel.</p>
    pub fn minimum_membership_percentage(&self) -> i32 {
        self.minimum_membership_percentage
    }
}
impl ElasticChannelConfiguration {
    /// Creates a new builder-style object to manufacture [`ElasticChannelConfiguration`](crate::types::ElasticChannelConfiguration).
    pub fn builder() -> crate::types::builders::ElasticChannelConfigurationBuilder {
        crate::types::builders::ElasticChannelConfigurationBuilder::default()
    }
}

/// A builder for [`ElasticChannelConfiguration`](crate::types::ElasticChannelConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ElasticChannelConfigurationBuilder {
    pub(crate) maximum_sub_channels: ::std::option::Option<i32>,
    pub(crate) target_memberships_per_sub_channel: ::std::option::Option<i32>,
    pub(crate) minimum_membership_percentage: ::std::option::Option<i32>,
}
impl ElasticChannelConfigurationBuilder {
    /// <p>The maximum number of SubChannels that you want to allow in the elastic channel.</p>
    /// This field is required.
    pub fn maximum_sub_channels(mut self, input: i32) -> Self {
        self.maximum_sub_channels = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of SubChannels that you want to allow in the elastic channel.</p>
    pub fn set_maximum_sub_channels(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_sub_channels = input;
        self
    }
    /// <p>The maximum number of SubChannels that you want to allow in the elastic channel.</p>
    pub fn get_maximum_sub_channels(&self) -> &::std::option::Option<i32> {
        &self.maximum_sub_channels
    }
    /// <p>The maximum number of members allowed in a SubChannel.</p>
    /// This field is required.
    pub fn target_memberships_per_sub_channel(mut self, input: i32) -> Self {
        self.target_memberships_per_sub_channel = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of members allowed in a SubChannel.</p>
    pub fn set_target_memberships_per_sub_channel(mut self, input: ::std::option::Option<i32>) -> Self {
        self.target_memberships_per_sub_channel = input;
        self
    }
    /// <p>The maximum number of members allowed in a SubChannel.</p>
    pub fn get_target_memberships_per_sub_channel(&self) -> &::std::option::Option<i32> {
        &self.target_memberships_per_sub_channel
    }
    /// <p>The minimum allowed percentage of TargetMembershipsPerSubChannel users. Ceil of the calculated value is used in balancing members among SubChannels of the elastic channel.</p>
    /// This field is required.
    pub fn minimum_membership_percentage(mut self, input: i32) -> Self {
        self.minimum_membership_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum allowed percentage of TargetMembershipsPerSubChannel users. Ceil of the calculated value is used in balancing members among SubChannels of the elastic channel.</p>
    pub fn set_minimum_membership_percentage(mut self, input: ::std::option::Option<i32>) -> Self {
        self.minimum_membership_percentage = input;
        self
    }
    /// <p>The minimum allowed percentage of TargetMembershipsPerSubChannel users. Ceil of the calculated value is used in balancing members among SubChannels of the elastic channel.</p>
    pub fn get_minimum_membership_percentage(&self) -> &::std::option::Option<i32> {
        &self.minimum_membership_percentage
    }
    /// Consumes the builder and constructs a [`ElasticChannelConfiguration`](crate::types::ElasticChannelConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`maximum_sub_channels`](crate::types::builders::ElasticChannelConfigurationBuilder::maximum_sub_channels)
    /// - [`target_memberships_per_sub_channel`](crate::types::builders::ElasticChannelConfigurationBuilder::target_memberships_per_sub_channel)
    /// - [`minimum_membership_percentage`](crate::types::builders::ElasticChannelConfigurationBuilder::minimum_membership_percentage)
    pub fn build(self) -> ::std::result::Result<crate::types::ElasticChannelConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ElasticChannelConfiguration {
            maximum_sub_channels: self.maximum_sub_channels.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "maximum_sub_channels",
                    "maximum_sub_channels was not specified but it is required when building ElasticChannelConfiguration",
                )
            })?,
            target_memberships_per_sub_channel: self.target_memberships_per_sub_channel.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "target_memberships_per_sub_channel",
                    "target_memberships_per_sub_channel was not specified but it is required when building ElasticChannelConfiguration",
                )
            })?,
            minimum_membership_percentage: self.minimum_membership_percentage.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "minimum_membership_percentage",
                    "minimum_membership_percentage was not specified but it is required when building ElasticChannelConfiguration",
                )
            })?,
        })
    }
}
