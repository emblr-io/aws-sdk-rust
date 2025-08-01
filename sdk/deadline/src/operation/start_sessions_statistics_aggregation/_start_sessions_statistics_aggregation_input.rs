// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartSessionsStatisticsAggregationInput {
    /// <p>The identifier of the farm that contains queues or fleets to return statistics for.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of fleet IDs or queue IDs to gather statistics for.</p>
    pub resource_ids: ::std::option::Option<crate::types::SessionsStatisticsResources>,
    /// <p>The Linux timestamp of the date and time that the statistics start.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Linux timestamp of the date and time that the statistics end.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timezone to use for the statistics. Use UTC notation such as "UTC+8."</p>
    pub timezone: ::std::option::Option<::std::string::String>,
    /// <p>The period to aggregate the statistics.</p>
    pub period: ::std::option::Option<crate::types::Period>,
    /// <p>The field to use to group the statistics.</p>
    pub group_by: ::std::option::Option<::std::vec::Vec<crate::types::UsageGroupByField>>,
    /// <p>One to four statistics to return.</p>
    pub statistics: ::std::option::Option<::std::vec::Vec<crate::types::UsageStatistic>>,
}
impl StartSessionsStatisticsAggregationInput {
    /// <p>The identifier of the farm that contains queues or fleets to return statistics for.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>A list of fleet IDs or queue IDs to gather statistics for.</p>
    pub fn resource_ids(&self) -> ::std::option::Option<&crate::types::SessionsStatisticsResources> {
        self.resource_ids.as_ref()
    }
    /// <p>The Linux timestamp of the date and time that the statistics start.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The Linux timestamp of the date and time that the statistics end.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The timezone to use for the statistics. Use UTC notation such as "UTC+8."</p>
    pub fn timezone(&self) -> ::std::option::Option<&str> {
        self.timezone.as_deref()
    }
    /// <p>The period to aggregate the statistics.</p>
    pub fn period(&self) -> ::std::option::Option<&crate::types::Period> {
        self.period.as_ref()
    }
    /// <p>The field to use to group the statistics.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.group_by.is_none()`.
    pub fn group_by(&self) -> &[crate::types::UsageGroupByField] {
        self.group_by.as_deref().unwrap_or_default()
    }
    /// <p>One to four statistics to return.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.statistics.is_none()`.
    pub fn statistics(&self) -> &[crate::types::UsageStatistic] {
        self.statistics.as_deref().unwrap_or_default()
    }
}
impl StartSessionsStatisticsAggregationInput {
    /// Creates a new builder-style object to manufacture [`StartSessionsStatisticsAggregationInput`](crate::operation::start_sessions_statistics_aggregation::StartSessionsStatisticsAggregationInput).
    pub fn builder() -> crate::operation::start_sessions_statistics_aggregation::builders::StartSessionsStatisticsAggregationInputBuilder {
        crate::operation::start_sessions_statistics_aggregation::builders::StartSessionsStatisticsAggregationInputBuilder::default()
    }
}

/// A builder for [`StartSessionsStatisticsAggregationInput`](crate::operation::start_sessions_statistics_aggregation::StartSessionsStatisticsAggregationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartSessionsStatisticsAggregationInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_ids: ::std::option::Option<crate::types::SessionsStatisticsResources>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) timezone: ::std::option::Option<::std::string::String>,
    pub(crate) period: ::std::option::Option<crate::types::Period>,
    pub(crate) group_by: ::std::option::Option<::std::vec::Vec<crate::types::UsageGroupByField>>,
    pub(crate) statistics: ::std::option::Option<::std::vec::Vec<crate::types::UsageStatistic>>,
}
impl StartSessionsStatisticsAggregationInputBuilder {
    /// <p>The identifier of the farm that contains queues or fleets to return statistics for.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the farm that contains queues or fleets to return statistics for.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The identifier of the farm that contains queues or fleets to return statistics for.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>A list of fleet IDs or queue IDs to gather statistics for.</p>
    /// This field is required.
    pub fn resource_ids(mut self, input: crate::types::SessionsStatisticsResources) -> Self {
        self.resource_ids = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of fleet IDs or queue IDs to gather statistics for.</p>
    pub fn set_resource_ids(mut self, input: ::std::option::Option<crate::types::SessionsStatisticsResources>) -> Self {
        self.resource_ids = input;
        self
    }
    /// <p>A list of fleet IDs or queue IDs to gather statistics for.</p>
    pub fn get_resource_ids(&self) -> &::std::option::Option<crate::types::SessionsStatisticsResources> {
        &self.resource_ids
    }
    /// <p>The Linux timestamp of the date and time that the statistics start.</p>
    /// This field is required.
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Linux timestamp of the date and time that the statistics start.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The Linux timestamp of the date and time that the statistics start.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The Linux timestamp of the date and time that the statistics end.</p>
    /// This field is required.
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Linux timestamp of the date and time that the statistics end.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The Linux timestamp of the date and time that the statistics end.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>The timezone to use for the statistics. Use UTC notation such as "UTC+8."</p>
    pub fn timezone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timezone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The timezone to use for the statistics. Use UTC notation such as "UTC+8."</p>
    pub fn set_timezone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timezone = input;
        self
    }
    /// <p>The timezone to use for the statistics. Use UTC notation such as "UTC+8."</p>
    pub fn get_timezone(&self) -> &::std::option::Option<::std::string::String> {
        &self.timezone
    }
    /// <p>The period to aggregate the statistics.</p>
    pub fn period(mut self, input: crate::types::Period) -> Self {
        self.period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The period to aggregate the statistics.</p>
    pub fn set_period(mut self, input: ::std::option::Option<crate::types::Period>) -> Self {
        self.period = input;
        self
    }
    /// <p>The period to aggregate the statistics.</p>
    pub fn get_period(&self) -> &::std::option::Option<crate::types::Period> {
        &self.period
    }
    /// Appends an item to `group_by`.
    ///
    /// To override the contents of this collection use [`set_group_by`](Self::set_group_by).
    ///
    /// <p>The field to use to group the statistics.</p>
    pub fn group_by(mut self, input: crate::types::UsageGroupByField) -> Self {
        let mut v = self.group_by.unwrap_or_default();
        v.push(input);
        self.group_by = ::std::option::Option::Some(v);
        self
    }
    /// <p>The field to use to group the statistics.</p>
    pub fn set_group_by(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UsageGroupByField>>) -> Self {
        self.group_by = input;
        self
    }
    /// <p>The field to use to group the statistics.</p>
    pub fn get_group_by(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UsageGroupByField>> {
        &self.group_by
    }
    /// Appends an item to `statistics`.
    ///
    /// To override the contents of this collection use [`set_statistics`](Self::set_statistics).
    ///
    /// <p>One to four statistics to return.</p>
    pub fn statistics(mut self, input: crate::types::UsageStatistic) -> Self {
        let mut v = self.statistics.unwrap_or_default();
        v.push(input);
        self.statistics = ::std::option::Option::Some(v);
        self
    }
    /// <p>One to four statistics to return.</p>
    pub fn set_statistics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UsageStatistic>>) -> Self {
        self.statistics = input;
        self
    }
    /// <p>One to four statistics to return.</p>
    pub fn get_statistics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UsageStatistic>> {
        &self.statistics
    }
    /// Consumes the builder and constructs a [`StartSessionsStatisticsAggregationInput`](crate::operation::start_sessions_statistics_aggregation::StartSessionsStatisticsAggregationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_sessions_statistics_aggregation::StartSessionsStatisticsAggregationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::start_sessions_statistics_aggregation::StartSessionsStatisticsAggregationInput {
                farm_id: self.farm_id,
                resource_ids: self.resource_ids,
                start_time: self.start_time,
                end_time: self.end_time,
                timezone: self.timezone,
                period: self.period,
                group_by: self.group_by,
                statistics: self.statistics,
            },
        )
    }
}
