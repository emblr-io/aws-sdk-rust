// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary of details of a channel flow.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ChannelFlowSummary {
    /// <p>The ARN of the channel flow.</p>
    pub channel_flow_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the channel flow.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Information about the processor Lambda functions.</p>
    pub processors: ::std::option::Option<::std::vec::Vec<crate::types::Processor>>,
}
impl ChannelFlowSummary {
    /// <p>The ARN of the channel flow.</p>
    pub fn channel_flow_arn(&self) -> ::std::option::Option<&str> {
        self.channel_flow_arn.as_deref()
    }
    /// <p>The name of the channel flow.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Information about the processor Lambda functions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.processors.is_none()`.
    pub fn processors(&self) -> &[crate::types::Processor] {
        self.processors.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for ChannelFlowSummary {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ChannelFlowSummary");
        formatter.field("channel_flow_arn", &self.channel_flow_arn);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("processors", &self.processors);
        formatter.finish()
    }
}
impl ChannelFlowSummary {
    /// Creates a new builder-style object to manufacture [`ChannelFlowSummary`](crate::types::ChannelFlowSummary).
    pub fn builder() -> crate::types::builders::ChannelFlowSummaryBuilder {
        crate::types::builders::ChannelFlowSummaryBuilder::default()
    }
}

/// A builder for [`ChannelFlowSummary`](crate::types::ChannelFlowSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ChannelFlowSummaryBuilder {
    pub(crate) channel_flow_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) processors: ::std::option::Option<::std::vec::Vec<crate::types::Processor>>,
}
impl ChannelFlowSummaryBuilder {
    /// <p>The ARN of the channel flow.</p>
    pub fn channel_flow_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_flow_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the channel flow.</p>
    pub fn set_channel_flow_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_flow_arn = input;
        self
    }
    /// <p>The ARN of the channel flow.</p>
    pub fn get_channel_flow_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_flow_arn
    }
    /// <p>The name of the channel flow.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the channel flow.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the channel flow.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `processors`.
    ///
    /// To override the contents of this collection use [`set_processors`](Self::set_processors).
    ///
    /// <p>Information about the processor Lambda functions.</p>
    pub fn processors(mut self, input: crate::types::Processor) -> Self {
        let mut v = self.processors.unwrap_or_default();
        v.push(input);
        self.processors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the processor Lambda functions.</p>
    pub fn set_processors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Processor>>) -> Self {
        self.processors = input;
        self
    }
    /// <p>Information about the processor Lambda functions.</p>
    pub fn get_processors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Processor>> {
        &self.processors
    }
    /// Consumes the builder and constructs a [`ChannelFlowSummary`](crate::types::ChannelFlowSummary).
    pub fn build(self) -> crate::types::ChannelFlowSummary {
        crate::types::ChannelFlowSummary {
            channel_flow_arn: self.channel_flow_arn,
            name: self.name,
            processors: self.processors,
        }
    }
}
impl ::std::fmt::Debug for ChannelFlowSummaryBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ChannelFlowSummaryBuilder");
        formatter.field("channel_flow_arn", &self.channel_flow_arn);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("processors", &self.processors);
        formatter.finish()
    }
}
