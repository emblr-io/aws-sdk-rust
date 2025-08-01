// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePrefetchScheduleOutput {
    /// <p>The ARN to assign to the prefetch schedule.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The configuration settings for how and when MediaTailor consumes prefetched ads from the ad decision server for single prefetch schedules. Each consumption configuration contains an end time and an optional start time that define the <i>consumption window</i>. Prefetch schedules automatically expire no earlier than seven days after the end time.</p>
    pub consumption: ::std::option::Option<crate::types::PrefetchConsumption>,
    /// <p>The name to assign to the prefetch schedule.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The name to assign to the playback configuration.</p>
    pub playback_configuration_name: ::std::option::Option<::std::string::String>,
    /// <p>The configuration settings for retrieval of prefetched ads from the ad decision server. Only one set of prefetched ads will be retrieved and subsequently consumed for each ad break.</p>
    pub retrieval: ::std::option::Option<crate::types::PrefetchRetrieval>,
    /// <p>The configuration that defines how MediaTailor performs recurring prefetch.</p>
    pub recurring_prefetch_configuration: ::std::option::Option<crate::types::RecurringPrefetchConfiguration>,
    /// <p>The frequency that MediaTailor creates prefetch schedules. <code>SINGLE</code> indicates that this schedule applies to one ad break. <code>RECURRING</code> indicates that MediaTailor automatically creates a schedule for each ad avail in a live event.</p>
    pub schedule_type: ::std::option::Option<crate::types::PrefetchScheduleType>,
    /// <p>An optional stream identifier that MediaTailor uses to prefetch ads for multiple streams that use the same playback configuration. If <code>StreamId</code> is specified, MediaTailor returns all of the prefetch schedules with an exact match on <code>StreamId</code>. If not specified, MediaTailor returns all of the prefetch schedules for the playback configuration, regardless of <code>StreamId</code>.</p>
    pub stream_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreatePrefetchScheduleOutput {
    /// <p>The ARN to assign to the prefetch schedule.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The configuration settings for how and when MediaTailor consumes prefetched ads from the ad decision server for single prefetch schedules. Each consumption configuration contains an end time and an optional start time that define the <i>consumption window</i>. Prefetch schedules automatically expire no earlier than seven days after the end time.</p>
    pub fn consumption(&self) -> ::std::option::Option<&crate::types::PrefetchConsumption> {
        self.consumption.as_ref()
    }
    /// <p>The name to assign to the prefetch schedule.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The name to assign to the playback configuration.</p>
    pub fn playback_configuration_name(&self) -> ::std::option::Option<&str> {
        self.playback_configuration_name.as_deref()
    }
    /// <p>The configuration settings for retrieval of prefetched ads from the ad decision server. Only one set of prefetched ads will be retrieved and subsequently consumed for each ad break.</p>
    pub fn retrieval(&self) -> ::std::option::Option<&crate::types::PrefetchRetrieval> {
        self.retrieval.as_ref()
    }
    /// <p>The configuration that defines how MediaTailor performs recurring prefetch.</p>
    pub fn recurring_prefetch_configuration(&self) -> ::std::option::Option<&crate::types::RecurringPrefetchConfiguration> {
        self.recurring_prefetch_configuration.as_ref()
    }
    /// <p>The frequency that MediaTailor creates prefetch schedules. <code>SINGLE</code> indicates that this schedule applies to one ad break. <code>RECURRING</code> indicates that MediaTailor automatically creates a schedule for each ad avail in a live event.</p>
    pub fn schedule_type(&self) -> ::std::option::Option<&crate::types::PrefetchScheduleType> {
        self.schedule_type.as_ref()
    }
    /// <p>An optional stream identifier that MediaTailor uses to prefetch ads for multiple streams that use the same playback configuration. If <code>StreamId</code> is specified, MediaTailor returns all of the prefetch schedules with an exact match on <code>StreamId</code>. If not specified, MediaTailor returns all of the prefetch schedules for the playback configuration, regardless of <code>StreamId</code>.</p>
    pub fn stream_id(&self) -> ::std::option::Option<&str> {
        self.stream_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreatePrefetchScheduleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreatePrefetchScheduleOutput {
    /// Creates a new builder-style object to manufacture [`CreatePrefetchScheduleOutput`](crate::operation::create_prefetch_schedule::CreatePrefetchScheduleOutput).
    pub fn builder() -> crate::operation::create_prefetch_schedule::builders::CreatePrefetchScheduleOutputBuilder {
        crate::operation::create_prefetch_schedule::builders::CreatePrefetchScheduleOutputBuilder::default()
    }
}

/// A builder for [`CreatePrefetchScheduleOutput`](crate::operation::create_prefetch_schedule::CreatePrefetchScheduleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePrefetchScheduleOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) consumption: ::std::option::Option<crate::types::PrefetchConsumption>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) playback_configuration_name: ::std::option::Option<::std::string::String>,
    pub(crate) retrieval: ::std::option::Option<crate::types::PrefetchRetrieval>,
    pub(crate) recurring_prefetch_configuration: ::std::option::Option<crate::types::RecurringPrefetchConfiguration>,
    pub(crate) schedule_type: ::std::option::Option<crate::types::PrefetchScheduleType>,
    pub(crate) stream_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreatePrefetchScheduleOutputBuilder {
    /// <p>The ARN to assign to the prefetch schedule.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN to assign to the prefetch schedule.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN to assign to the prefetch schedule.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The configuration settings for how and when MediaTailor consumes prefetched ads from the ad decision server for single prefetch schedules. Each consumption configuration contains an end time and an optional start time that define the <i>consumption window</i>. Prefetch schedules automatically expire no earlier than seven days after the end time.</p>
    pub fn consumption(mut self, input: crate::types::PrefetchConsumption) -> Self {
        self.consumption = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration settings for how and when MediaTailor consumes prefetched ads from the ad decision server for single prefetch schedules. Each consumption configuration contains an end time and an optional start time that define the <i>consumption window</i>. Prefetch schedules automatically expire no earlier than seven days after the end time.</p>
    pub fn set_consumption(mut self, input: ::std::option::Option<crate::types::PrefetchConsumption>) -> Self {
        self.consumption = input;
        self
    }
    /// <p>The configuration settings for how and when MediaTailor consumes prefetched ads from the ad decision server for single prefetch schedules. Each consumption configuration contains an end time and an optional start time that define the <i>consumption window</i>. Prefetch schedules automatically expire no earlier than seven days after the end time.</p>
    pub fn get_consumption(&self) -> &::std::option::Option<crate::types::PrefetchConsumption> {
        &self.consumption
    }
    /// <p>The name to assign to the prefetch schedule.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name to assign to the prefetch schedule.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name to assign to the prefetch schedule.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The name to assign to the playback configuration.</p>
    pub fn playback_configuration_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.playback_configuration_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name to assign to the playback configuration.</p>
    pub fn set_playback_configuration_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.playback_configuration_name = input;
        self
    }
    /// <p>The name to assign to the playback configuration.</p>
    pub fn get_playback_configuration_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.playback_configuration_name
    }
    /// <p>The configuration settings for retrieval of prefetched ads from the ad decision server. Only one set of prefetched ads will be retrieved and subsequently consumed for each ad break.</p>
    pub fn retrieval(mut self, input: crate::types::PrefetchRetrieval) -> Self {
        self.retrieval = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration settings for retrieval of prefetched ads from the ad decision server. Only one set of prefetched ads will be retrieved and subsequently consumed for each ad break.</p>
    pub fn set_retrieval(mut self, input: ::std::option::Option<crate::types::PrefetchRetrieval>) -> Self {
        self.retrieval = input;
        self
    }
    /// <p>The configuration settings for retrieval of prefetched ads from the ad decision server. Only one set of prefetched ads will be retrieved and subsequently consumed for each ad break.</p>
    pub fn get_retrieval(&self) -> &::std::option::Option<crate::types::PrefetchRetrieval> {
        &self.retrieval
    }
    /// <p>The configuration that defines how MediaTailor performs recurring prefetch.</p>
    pub fn recurring_prefetch_configuration(mut self, input: crate::types::RecurringPrefetchConfiguration) -> Self {
        self.recurring_prefetch_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration that defines how MediaTailor performs recurring prefetch.</p>
    pub fn set_recurring_prefetch_configuration(mut self, input: ::std::option::Option<crate::types::RecurringPrefetchConfiguration>) -> Self {
        self.recurring_prefetch_configuration = input;
        self
    }
    /// <p>The configuration that defines how MediaTailor performs recurring prefetch.</p>
    pub fn get_recurring_prefetch_configuration(&self) -> &::std::option::Option<crate::types::RecurringPrefetchConfiguration> {
        &self.recurring_prefetch_configuration
    }
    /// <p>The frequency that MediaTailor creates prefetch schedules. <code>SINGLE</code> indicates that this schedule applies to one ad break. <code>RECURRING</code> indicates that MediaTailor automatically creates a schedule for each ad avail in a live event.</p>
    pub fn schedule_type(mut self, input: crate::types::PrefetchScheduleType) -> Self {
        self.schedule_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The frequency that MediaTailor creates prefetch schedules. <code>SINGLE</code> indicates that this schedule applies to one ad break. <code>RECURRING</code> indicates that MediaTailor automatically creates a schedule for each ad avail in a live event.</p>
    pub fn set_schedule_type(mut self, input: ::std::option::Option<crate::types::PrefetchScheduleType>) -> Self {
        self.schedule_type = input;
        self
    }
    /// <p>The frequency that MediaTailor creates prefetch schedules. <code>SINGLE</code> indicates that this schedule applies to one ad break. <code>RECURRING</code> indicates that MediaTailor automatically creates a schedule for each ad avail in a live event.</p>
    pub fn get_schedule_type(&self) -> &::std::option::Option<crate::types::PrefetchScheduleType> {
        &self.schedule_type
    }
    /// <p>An optional stream identifier that MediaTailor uses to prefetch ads for multiple streams that use the same playback configuration. If <code>StreamId</code> is specified, MediaTailor returns all of the prefetch schedules with an exact match on <code>StreamId</code>. If not specified, MediaTailor returns all of the prefetch schedules for the playback configuration, regardless of <code>StreamId</code>.</p>
    pub fn stream_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional stream identifier that MediaTailor uses to prefetch ads for multiple streams that use the same playback configuration. If <code>StreamId</code> is specified, MediaTailor returns all of the prefetch schedules with an exact match on <code>StreamId</code>. If not specified, MediaTailor returns all of the prefetch schedules for the playback configuration, regardless of <code>StreamId</code>.</p>
    pub fn set_stream_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_id = input;
        self
    }
    /// <p>An optional stream identifier that MediaTailor uses to prefetch ads for multiple streams that use the same playback configuration. If <code>StreamId</code> is specified, MediaTailor returns all of the prefetch schedules with an exact match on <code>StreamId</code>. If not specified, MediaTailor returns all of the prefetch schedules for the playback configuration, regardless of <code>StreamId</code>.</p>
    pub fn get_stream_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreatePrefetchScheduleOutput`](crate::operation::create_prefetch_schedule::CreatePrefetchScheduleOutput).
    pub fn build(self) -> crate::operation::create_prefetch_schedule::CreatePrefetchScheduleOutput {
        crate::operation::create_prefetch_schedule::CreatePrefetchScheduleOutput {
            arn: self.arn,
            consumption: self.consumption,
            name: self.name,
            playback_configuration_name: self.playback_configuration_name,
            retrieval: self.retrieval,
            recurring_prefetch_configuration: self.recurring_prefetch_configuration,
            schedule_type: self.schedule_type,
            stream_id: self.stream_id,
            _request_id: self._request_id,
        }
    }
}
