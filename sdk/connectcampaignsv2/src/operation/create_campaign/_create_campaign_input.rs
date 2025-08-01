// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// The request for CreateCampaign API.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCampaignInput {
    /// The name of an Amazon Connect Campaign name.
    pub name: ::std::option::Option<::std::string::String>,
    /// Amazon Connect Instance Id
    pub connect_instance_id: ::std::option::Option<::std::string::String>,
    /// Campaign Channel Subtype config
    pub channel_subtype_config: ::std::option::Option<crate::types::ChannelSubtypeConfig>,
    /// Source of the campaign
    pub source: ::std::option::Option<crate::types::Source>,
    /// Amazon Resource Names(ARN)
    pub connect_campaign_flow_arn: ::std::option::Option<::std::string::String>,
    /// Campaign schedule
    pub schedule: ::std::option::Option<crate::types::Schedule>,
    /// Campaign communication time config
    pub communication_time_config: ::std::option::Option<crate::types::CommunicationTimeConfig>,
    /// Communication limits config
    pub communication_limits_override: ::std::option::Option<crate::types::CommunicationLimitsConfig>,
    /// Tag map with key and value.
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateCampaignInput {
    /// The name of an Amazon Connect Campaign name.
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// Amazon Connect Instance Id
    pub fn connect_instance_id(&self) -> ::std::option::Option<&str> {
        self.connect_instance_id.as_deref()
    }
    /// Campaign Channel Subtype config
    pub fn channel_subtype_config(&self) -> ::std::option::Option<&crate::types::ChannelSubtypeConfig> {
        self.channel_subtype_config.as_ref()
    }
    /// Source of the campaign
    pub fn source(&self) -> ::std::option::Option<&crate::types::Source> {
        self.source.as_ref()
    }
    /// Amazon Resource Names(ARN)
    pub fn connect_campaign_flow_arn(&self) -> ::std::option::Option<&str> {
        self.connect_campaign_flow_arn.as_deref()
    }
    /// Campaign schedule
    pub fn schedule(&self) -> ::std::option::Option<&crate::types::Schedule> {
        self.schedule.as_ref()
    }
    /// Campaign communication time config
    pub fn communication_time_config(&self) -> ::std::option::Option<&crate::types::CommunicationTimeConfig> {
        self.communication_time_config.as_ref()
    }
    /// Communication limits config
    pub fn communication_limits_override(&self) -> ::std::option::Option<&crate::types::CommunicationLimitsConfig> {
        self.communication_limits_override.as_ref()
    }
    /// Tag map with key and value.
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateCampaignInput {
    /// Creates a new builder-style object to manufacture [`CreateCampaignInput`](crate::operation::create_campaign::CreateCampaignInput).
    pub fn builder() -> crate::operation::create_campaign::builders::CreateCampaignInputBuilder {
        crate::operation::create_campaign::builders::CreateCampaignInputBuilder::default()
    }
}

/// A builder for [`CreateCampaignInput`](crate::operation::create_campaign::CreateCampaignInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCampaignInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) connect_instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) channel_subtype_config: ::std::option::Option<crate::types::ChannelSubtypeConfig>,
    pub(crate) source: ::std::option::Option<crate::types::Source>,
    pub(crate) connect_campaign_flow_arn: ::std::option::Option<::std::string::String>,
    pub(crate) schedule: ::std::option::Option<crate::types::Schedule>,
    pub(crate) communication_time_config: ::std::option::Option<crate::types::CommunicationTimeConfig>,
    pub(crate) communication_limits_override: ::std::option::Option<crate::types::CommunicationLimitsConfig>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateCampaignInputBuilder {
    /// The name of an Amazon Connect Campaign name.
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// The name of an Amazon Connect Campaign name.
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// The name of an Amazon Connect Campaign name.
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Amazon Connect Instance Id
    /// This field is required.
    pub fn connect_instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connect_instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// Amazon Connect Instance Id
    pub fn set_connect_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connect_instance_id = input;
        self
    }
    /// Amazon Connect Instance Id
    pub fn get_connect_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connect_instance_id
    }
    /// Campaign Channel Subtype config
    /// This field is required.
    pub fn channel_subtype_config(mut self, input: crate::types::ChannelSubtypeConfig) -> Self {
        self.channel_subtype_config = ::std::option::Option::Some(input);
        self
    }
    /// Campaign Channel Subtype config
    pub fn set_channel_subtype_config(mut self, input: ::std::option::Option<crate::types::ChannelSubtypeConfig>) -> Self {
        self.channel_subtype_config = input;
        self
    }
    /// Campaign Channel Subtype config
    pub fn get_channel_subtype_config(&self) -> &::std::option::Option<crate::types::ChannelSubtypeConfig> {
        &self.channel_subtype_config
    }
    /// Source of the campaign
    pub fn source(mut self, input: crate::types::Source) -> Self {
        self.source = ::std::option::Option::Some(input);
        self
    }
    /// Source of the campaign
    pub fn set_source(mut self, input: ::std::option::Option<crate::types::Source>) -> Self {
        self.source = input;
        self
    }
    /// Source of the campaign
    pub fn get_source(&self) -> &::std::option::Option<crate::types::Source> {
        &self.source
    }
    /// Amazon Resource Names(ARN)
    pub fn connect_campaign_flow_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connect_campaign_flow_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// Amazon Resource Names(ARN)
    pub fn set_connect_campaign_flow_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connect_campaign_flow_arn = input;
        self
    }
    /// Amazon Resource Names(ARN)
    pub fn get_connect_campaign_flow_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.connect_campaign_flow_arn
    }
    /// Campaign schedule
    pub fn schedule(mut self, input: crate::types::Schedule) -> Self {
        self.schedule = ::std::option::Option::Some(input);
        self
    }
    /// Campaign schedule
    pub fn set_schedule(mut self, input: ::std::option::Option<crate::types::Schedule>) -> Self {
        self.schedule = input;
        self
    }
    /// Campaign schedule
    pub fn get_schedule(&self) -> &::std::option::Option<crate::types::Schedule> {
        &self.schedule
    }
    /// Campaign communication time config
    pub fn communication_time_config(mut self, input: crate::types::CommunicationTimeConfig) -> Self {
        self.communication_time_config = ::std::option::Option::Some(input);
        self
    }
    /// Campaign communication time config
    pub fn set_communication_time_config(mut self, input: ::std::option::Option<crate::types::CommunicationTimeConfig>) -> Self {
        self.communication_time_config = input;
        self
    }
    /// Campaign communication time config
    pub fn get_communication_time_config(&self) -> &::std::option::Option<crate::types::CommunicationTimeConfig> {
        &self.communication_time_config
    }
    /// Communication limits config
    pub fn communication_limits_override(mut self, input: crate::types::CommunicationLimitsConfig) -> Self {
        self.communication_limits_override = ::std::option::Option::Some(input);
        self
    }
    /// Communication limits config
    pub fn set_communication_limits_override(mut self, input: ::std::option::Option<crate::types::CommunicationLimitsConfig>) -> Self {
        self.communication_limits_override = input;
        self
    }
    /// Communication limits config
    pub fn get_communication_limits_override(&self) -> &::std::option::Option<crate::types::CommunicationLimitsConfig> {
        &self.communication_limits_override
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// Tag map with key and value.
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// Tag map with key and value.
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// Tag map with key and value.
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateCampaignInput`](crate::operation::create_campaign::CreateCampaignInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_campaign::CreateCampaignInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_campaign::CreateCampaignInput {
            name: self.name,
            connect_instance_id: self.connect_instance_id,
            channel_subtype_config: self.channel_subtype_config,
            source: self.source,
            connect_campaign_flow_arn: self.connect_campaign_flow_arn,
            schedule: self.schedule,
            communication_time_config: self.communication_time_config,
            communication_limits_override: self.communication_limits_override,
            tags: self.tags,
        })
    }
}
