// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The structure representing the BatchGetFrameMetricDataResponse.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetFrameMetricDataOutput {
    /// <p>The start time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub start_time: ::aws_smithy_types::DateTime,
    /// <p>The end time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub end_time: ::aws_smithy_types::DateTime,
    /// <p>Resolution or granularity of the profile data used to generate the time series. This is the value used to jump through time steps in a time series. There are 3 valid values.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    pub resolution: crate::types::AggregationPeriod,
    /// <p>List of instances, or time steps, in the time series. For example, if the <code>period</code> is one day (<code>PT24H)</code>), and the <code>resolution</code> is five minutes (<code>PT5M</code>), then there are 288 <code>endTimes</code> in the list that are each five minutes appart.</p>
    pub end_times: ::std::vec::Vec<crate::types::TimestampStructure>,
    /// <p>List of instances which remained unprocessed. This will create a missing time step in the list of end times.</p>
    pub unprocessed_end_times: ::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::TimestampStructure>>,
    /// <p>Details of the metrics to request a time series of values. The metric includes the name of the frame, the aggregation type to calculate the metric value for the frame, and the thread states to use to get the count for the metric value of the frame.</p>
    pub frame_metric_data: ::std::vec::Vec<crate::types::FrameMetricDatum>,
    _request_id: Option<String>,
}
impl BatchGetFrameMetricDataOutput {
    /// <p>The start time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn start_time(&self) -> &::aws_smithy_types::DateTime {
        &self.start_time
    }
    /// <p>The end time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn end_time(&self) -> &::aws_smithy_types::DateTime {
        &self.end_time
    }
    /// <p>Resolution or granularity of the profile data used to generate the time series. This is the value used to jump through time steps in a time series. There are 3 valid values.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    pub fn resolution(&self) -> &crate::types::AggregationPeriod {
        &self.resolution
    }
    /// <p>List of instances, or time steps, in the time series. For example, if the <code>period</code> is one day (<code>PT24H)</code>), and the <code>resolution</code> is five minutes (<code>PT5M</code>), then there are 288 <code>endTimes</code> in the list that are each five minutes appart.</p>
    pub fn end_times(&self) -> &[crate::types::TimestampStructure] {
        use std::ops::Deref;
        self.end_times.deref()
    }
    /// <p>List of instances which remained unprocessed. This will create a missing time step in the list of end times.</p>
    pub fn unprocessed_end_times(&self) -> &::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::TimestampStructure>> {
        &self.unprocessed_end_times
    }
    /// <p>Details of the metrics to request a time series of values. The metric includes the name of the frame, the aggregation type to calculate the metric value for the frame, and the thread states to use to get the count for the metric value of the frame.</p>
    pub fn frame_metric_data(&self) -> &[crate::types::FrameMetricDatum] {
        use std::ops::Deref;
        self.frame_metric_data.deref()
    }
}
impl ::aws_types::request_id::RequestId for BatchGetFrameMetricDataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchGetFrameMetricDataOutput {
    /// Creates a new builder-style object to manufacture [`BatchGetFrameMetricDataOutput`](crate::operation::batch_get_frame_metric_data::BatchGetFrameMetricDataOutput).
    pub fn builder() -> crate::operation::batch_get_frame_metric_data::builders::BatchGetFrameMetricDataOutputBuilder {
        crate::operation::batch_get_frame_metric_data::builders::BatchGetFrameMetricDataOutputBuilder::default()
    }
}

/// A builder for [`BatchGetFrameMetricDataOutput`](crate::operation::batch_get_frame_metric_data::BatchGetFrameMetricDataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetFrameMetricDataOutputBuilder {
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) resolution: ::std::option::Option<crate::types::AggregationPeriod>,
    pub(crate) end_times: ::std::option::Option<::std::vec::Vec<crate::types::TimestampStructure>>,
    pub(crate) unprocessed_end_times:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::TimestampStructure>>>,
    pub(crate) frame_metric_data: ::std::option::Option<::std::vec::Vec<crate::types::FrameMetricDatum>>,
    _request_id: Option<String>,
}
impl BatchGetFrameMetricDataOutputBuilder {
    /// <p>The start time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    /// This field is required.
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The end time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    /// This field is required.
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end time of the time period for the returned time series values. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>Resolution or granularity of the profile data used to generate the time series. This is the value used to jump through time steps in a time series. There are 3 valid values.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    /// This field is required.
    pub fn resolution(mut self, input: crate::types::AggregationPeriod) -> Self {
        self.resolution = ::std::option::Option::Some(input);
        self
    }
    /// <p>Resolution or granularity of the profile data used to generate the time series. This is the value used to jump through time steps in a time series. There are 3 valid values.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    pub fn set_resolution(mut self, input: ::std::option::Option<crate::types::AggregationPeriod>) -> Self {
        self.resolution = input;
        self
    }
    /// <p>Resolution or granularity of the profile data used to generate the time series. This is the value used to jump through time steps in a time series. There are 3 valid values.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    pub fn get_resolution(&self) -> &::std::option::Option<crate::types::AggregationPeriod> {
        &self.resolution
    }
    /// Appends an item to `end_times`.
    ///
    /// To override the contents of this collection use [`set_end_times`](Self::set_end_times).
    ///
    /// <p>List of instances, or time steps, in the time series. For example, if the <code>period</code> is one day (<code>PT24H)</code>), and the <code>resolution</code> is five minutes (<code>PT5M</code>), then there are 288 <code>endTimes</code> in the list that are each five minutes appart.</p>
    pub fn end_times(mut self, input: crate::types::TimestampStructure) -> Self {
        let mut v = self.end_times.unwrap_or_default();
        v.push(input);
        self.end_times = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of instances, or time steps, in the time series. For example, if the <code>period</code> is one day (<code>PT24H)</code>), and the <code>resolution</code> is five minutes (<code>PT5M</code>), then there are 288 <code>endTimes</code> in the list that are each five minutes appart.</p>
    pub fn set_end_times(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TimestampStructure>>) -> Self {
        self.end_times = input;
        self
    }
    /// <p>List of instances, or time steps, in the time series. For example, if the <code>period</code> is one day (<code>PT24H)</code>), and the <code>resolution</code> is five minutes (<code>PT5M</code>), then there are 288 <code>endTimes</code> in the list that are each five minutes appart.</p>
    pub fn get_end_times(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TimestampStructure>> {
        &self.end_times
    }
    /// Adds a key-value pair to `unprocessed_end_times`.
    ///
    /// To override the contents of this collection use [`set_unprocessed_end_times`](Self::set_unprocessed_end_times).
    ///
    /// <p>List of instances which remained unprocessed. This will create a missing time step in the list of end times.</p>
    pub fn unprocessed_end_times(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: ::std::vec::Vec<crate::types::TimestampStructure>,
    ) -> Self {
        let mut hash_map = self.unprocessed_end_times.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.unprocessed_end_times = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>List of instances which remained unprocessed. This will create a missing time step in the list of end times.</p>
    pub fn set_unprocessed_end_times(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::TimestampStructure>>>,
    ) -> Self {
        self.unprocessed_end_times = input;
        self
    }
    /// <p>List of instances which remained unprocessed. This will create a missing time step in the list of end times.</p>
    pub fn get_unprocessed_end_times(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::TimestampStructure>>> {
        &self.unprocessed_end_times
    }
    /// Appends an item to `frame_metric_data`.
    ///
    /// To override the contents of this collection use [`set_frame_metric_data`](Self::set_frame_metric_data).
    ///
    /// <p>Details of the metrics to request a time series of values. The metric includes the name of the frame, the aggregation type to calculate the metric value for the frame, and the thread states to use to get the count for the metric value of the frame.</p>
    pub fn frame_metric_data(mut self, input: crate::types::FrameMetricDatum) -> Self {
        let mut v = self.frame_metric_data.unwrap_or_default();
        v.push(input);
        self.frame_metric_data = ::std::option::Option::Some(v);
        self
    }
    /// <p>Details of the metrics to request a time series of values. The metric includes the name of the frame, the aggregation type to calculate the metric value for the frame, and the thread states to use to get the count for the metric value of the frame.</p>
    pub fn set_frame_metric_data(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FrameMetricDatum>>) -> Self {
        self.frame_metric_data = input;
        self
    }
    /// <p>Details of the metrics to request a time series of values. The metric includes the name of the frame, the aggregation type to calculate the metric value for the frame, and the thread states to use to get the count for the metric value of the frame.</p>
    pub fn get_frame_metric_data(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FrameMetricDatum>> {
        &self.frame_metric_data
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchGetFrameMetricDataOutput`](crate::operation::batch_get_frame_metric_data::BatchGetFrameMetricDataOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`start_time`](crate::operation::batch_get_frame_metric_data::builders::BatchGetFrameMetricDataOutputBuilder::start_time)
    /// - [`end_time`](crate::operation::batch_get_frame_metric_data::builders::BatchGetFrameMetricDataOutputBuilder::end_time)
    /// - [`resolution`](crate::operation::batch_get_frame_metric_data::builders::BatchGetFrameMetricDataOutputBuilder::resolution)
    /// - [`end_times`](crate::operation::batch_get_frame_metric_data::builders::BatchGetFrameMetricDataOutputBuilder::end_times)
    /// - [`unprocessed_end_times`](crate::operation::batch_get_frame_metric_data::builders::BatchGetFrameMetricDataOutputBuilder::unprocessed_end_times)
    /// - [`frame_metric_data`](crate::operation::batch_get_frame_metric_data::builders::BatchGetFrameMetricDataOutputBuilder::frame_metric_data)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_get_frame_metric_data::BatchGetFrameMetricDataOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::batch_get_frame_metric_data::BatchGetFrameMetricDataOutput {
            start_time: self.start_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "start_time",
                    "start_time was not specified but it is required when building BatchGetFrameMetricDataOutput",
                )
            })?,
            end_time: self.end_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "end_time",
                    "end_time was not specified but it is required when building BatchGetFrameMetricDataOutput",
                )
            })?,
            resolution: self.resolution.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resolution",
                    "resolution was not specified but it is required when building BatchGetFrameMetricDataOutput",
                )
            })?,
            end_times: self.end_times.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "end_times",
                    "end_times was not specified but it is required when building BatchGetFrameMetricDataOutput",
                )
            })?,
            unprocessed_end_times: self.unprocessed_end_times.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "unprocessed_end_times",
                    "unprocessed_end_times was not specified but it is required when building BatchGetFrameMetricDataOutput",
                )
            })?,
            frame_metric_data: self.frame_metric_data.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "frame_metric_data",
                    "frame_metric_data was not specified but it is required when building BatchGetFrameMetricDataOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
