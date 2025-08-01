// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SampleChannelDataInput {
    /// <p>The name of the channel whose message samples are retrieved.</p>
    pub channel_name: ::std::option::Option<::std::string::String>,
    /// <p>The number of sample messages to be retrieved. The limit is 10. The default is also 10.</p>
    pub max_messages: ::std::option::Option<i32>,
    /// <p>The start of the time window from which sample messages are retrieved.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end of the time window from which sample messages are retrieved.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SampleChannelDataInput {
    /// <p>The name of the channel whose message samples are retrieved.</p>
    pub fn channel_name(&self) -> ::std::option::Option<&str> {
        self.channel_name.as_deref()
    }
    /// <p>The number of sample messages to be retrieved. The limit is 10. The default is also 10.</p>
    pub fn max_messages(&self) -> ::std::option::Option<i32> {
        self.max_messages
    }
    /// <p>The start of the time window from which sample messages are retrieved.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The end of the time window from which sample messages are retrieved.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
}
impl SampleChannelDataInput {
    /// Creates a new builder-style object to manufacture [`SampleChannelDataInput`](crate::operation::sample_channel_data::SampleChannelDataInput).
    pub fn builder() -> crate::operation::sample_channel_data::builders::SampleChannelDataInputBuilder {
        crate::operation::sample_channel_data::builders::SampleChannelDataInputBuilder::default()
    }
}

/// A builder for [`SampleChannelDataInput`](crate::operation::sample_channel_data::SampleChannelDataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SampleChannelDataInputBuilder {
    pub(crate) channel_name: ::std::option::Option<::std::string::String>,
    pub(crate) max_messages: ::std::option::Option<i32>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SampleChannelDataInputBuilder {
    /// <p>The name of the channel whose message samples are retrieved.</p>
    /// This field is required.
    pub fn channel_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the channel whose message samples are retrieved.</p>
    pub fn set_channel_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_name = input;
        self
    }
    /// <p>The name of the channel whose message samples are retrieved.</p>
    pub fn get_channel_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_name
    }
    /// <p>The number of sample messages to be retrieved. The limit is 10. The default is also 10.</p>
    pub fn max_messages(mut self, input: i32) -> Self {
        self.max_messages = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of sample messages to be retrieved. The limit is 10. The default is also 10.</p>
    pub fn set_max_messages(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_messages = input;
        self
    }
    /// <p>The number of sample messages to be retrieved. The limit is 10. The default is also 10.</p>
    pub fn get_max_messages(&self) -> &::std::option::Option<i32> {
        &self.max_messages
    }
    /// <p>The start of the time window from which sample messages are retrieved.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start of the time window from which sample messages are retrieved.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start of the time window from which sample messages are retrieved.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The end of the time window from which sample messages are retrieved.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end of the time window from which sample messages are retrieved.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end of the time window from which sample messages are retrieved.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Consumes the builder and constructs a [`SampleChannelDataInput`](crate::operation::sample_channel_data::SampleChannelDataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::sample_channel_data::SampleChannelDataInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::sample_channel_data::SampleChannelDataInput {
            channel_name: self.channel_name,
            max_messages: self.max_messages,
            start_time: self.start_time,
            end_time: self.end_time,
        })
    }
}
