// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInterpolatedAssetPropertyValuesInput {
    /// <p>The ID of the asset, in UUID format.</p>
    pub asset_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the asset property, in UUID format.</p>
    pub property_id: ::std::option::Option<::std::string::String>,
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub property_alias: ::std::option::Option<::std::string::String>,
    /// <p>The exclusive start of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    pub start_time_in_seconds: ::std::option::Option<i64>,
    /// <p>The nanosecond offset converted from <code>startTimeInSeconds</code>.</p>
    pub start_time_offset_in_nanos: ::std::option::Option<i32>,
    /// <p>The inclusive end of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    pub end_time_in_seconds: ::std::option::Option<i64>,
    /// <p>The nanosecond offset converted from <code>endTimeInSeconds</code>.</p>
    pub end_time_offset_in_nanos: ::std::option::Option<i32>,
    /// <p>The quality of the asset property value. You can use this parameter as a filter to choose only the asset property values that have a specific quality.</p>
    pub quality: ::std::option::Option<crate::types::Quality>,
    /// <p>The time interval in seconds over which to interpolate data. Each interval starts when the previous one ends.</p>
    pub interval_in_seconds: ::std::option::Option<i64>,
    /// <p>The token to be used for the next set of paginated results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return for each paginated request. If not specified, the default value is 10.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The interpolation type.</p>
    /// <p>Valid values: <code>LINEAR_INTERPOLATION | LOCF_INTERPOLATION</code></p>
    /// <ul>
    /// <li>
    /// <p><code>LINEAR_INTERPOLATION</code> – Estimates missing data using <a href="https://en.wikipedia.org/wiki/Linear_interpolation">linear interpolation</a>.</p>
    /// <p>For example, you can use this operation to return the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the first interpolated value on July 2, 2021, at 9 AM, the second interpolated value on July 3, 2021, at 9 AM, and so on.</p></li>
    /// <li>
    /// <p><code>LOCF_INTERPOLATION</code> – Estimates missing data using last observation carried forward interpolation</p>
    /// <p>If no data point is found for an interval, IoT SiteWise returns the last observed data point for the previous interval and carries forward this interpolated value until a new data point is found.</p>
    /// <p>For example, you can get the state of an on-off valve every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the last observed data point between July 1, 2021, at 9 AM and July 2, 2021, at 9 AM as the first interpolated value. If a data point isn't found after 9 AM on July 2, 2021, IoT SiteWise uses the same interpolated value for the rest of the days.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The query interval for the window, in seconds. IoT SiteWise computes each interpolated value by using data points from the timestamp of each interval, minus the window to the timestamp of each interval plus the window. If not specified, the window ranges between the start time minus the interval and the end time plus the interval.</p><note>
    /// <ul>
    /// <li>
    /// <p>If you specify a value for the <code>intervalWindowInSeconds</code> parameter, the value for the <code>type</code> parameter must be <code>LINEAR_INTERPOLATION</code>.</p></li>
    /// <li>
    /// <p>If a data point isn't found during the specified query window, IoT SiteWise won't return an interpolated value for the interval. This indicates that there's a gap in the ingested data points.</p></li>
    /// </ul>
    /// </note>
    /// <p>For example, you can get the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts on July 1, 2021, at 9 AM with a window of 2 hours, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 2, 2021 to compute the first interpolated value. Next, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 3, 2021 to compute the second interpolated value, and so on.</p>
    pub interval_window_in_seconds: ::std::option::Option<i64>,
}
impl GetInterpolatedAssetPropertyValuesInput {
    /// <p>The ID of the asset, in UUID format.</p>
    pub fn asset_id(&self) -> ::std::option::Option<&str> {
        self.asset_id.as_deref()
    }
    /// <p>The ID of the asset property, in UUID format.</p>
    pub fn property_id(&self) -> ::std::option::Option<&str> {
        self.property_id.as_deref()
    }
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn property_alias(&self) -> ::std::option::Option<&str> {
        self.property_alias.as_deref()
    }
    /// <p>The exclusive start of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    pub fn start_time_in_seconds(&self) -> ::std::option::Option<i64> {
        self.start_time_in_seconds
    }
    /// <p>The nanosecond offset converted from <code>startTimeInSeconds</code>.</p>
    pub fn start_time_offset_in_nanos(&self) -> ::std::option::Option<i32> {
        self.start_time_offset_in_nanos
    }
    /// <p>The inclusive end of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    pub fn end_time_in_seconds(&self) -> ::std::option::Option<i64> {
        self.end_time_in_seconds
    }
    /// <p>The nanosecond offset converted from <code>endTimeInSeconds</code>.</p>
    pub fn end_time_offset_in_nanos(&self) -> ::std::option::Option<i32> {
        self.end_time_offset_in_nanos
    }
    /// <p>The quality of the asset property value. You can use this parameter as a filter to choose only the asset property values that have a specific quality.</p>
    pub fn quality(&self) -> ::std::option::Option<&crate::types::Quality> {
        self.quality.as_ref()
    }
    /// <p>The time interval in seconds over which to interpolate data. Each interval starts when the previous one ends.</p>
    pub fn interval_in_seconds(&self) -> ::std::option::Option<i64> {
        self.interval_in_seconds
    }
    /// <p>The token to be used for the next set of paginated results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return for each paginated request. If not specified, the default value is 10.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The interpolation type.</p>
    /// <p>Valid values: <code>LINEAR_INTERPOLATION | LOCF_INTERPOLATION</code></p>
    /// <ul>
    /// <li>
    /// <p><code>LINEAR_INTERPOLATION</code> – Estimates missing data using <a href="https://en.wikipedia.org/wiki/Linear_interpolation">linear interpolation</a>.</p>
    /// <p>For example, you can use this operation to return the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the first interpolated value on July 2, 2021, at 9 AM, the second interpolated value on July 3, 2021, at 9 AM, and so on.</p></li>
    /// <li>
    /// <p><code>LOCF_INTERPOLATION</code> – Estimates missing data using last observation carried forward interpolation</p>
    /// <p>If no data point is found for an interval, IoT SiteWise returns the last observed data point for the previous interval and carries forward this interpolated value until a new data point is found.</p>
    /// <p>For example, you can get the state of an on-off valve every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the last observed data point between July 1, 2021, at 9 AM and July 2, 2021, at 9 AM as the first interpolated value. If a data point isn't found after 9 AM on July 2, 2021, IoT SiteWise uses the same interpolated value for the rest of the days.</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The query interval for the window, in seconds. IoT SiteWise computes each interpolated value by using data points from the timestamp of each interval, minus the window to the timestamp of each interval plus the window. If not specified, the window ranges between the start time minus the interval and the end time plus the interval.</p><note>
    /// <ul>
    /// <li>
    /// <p>If you specify a value for the <code>intervalWindowInSeconds</code> parameter, the value for the <code>type</code> parameter must be <code>LINEAR_INTERPOLATION</code>.</p></li>
    /// <li>
    /// <p>If a data point isn't found during the specified query window, IoT SiteWise won't return an interpolated value for the interval. This indicates that there's a gap in the ingested data points.</p></li>
    /// </ul>
    /// </note>
    /// <p>For example, you can get the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts on July 1, 2021, at 9 AM with a window of 2 hours, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 2, 2021 to compute the first interpolated value. Next, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 3, 2021 to compute the second interpolated value, and so on.</p>
    pub fn interval_window_in_seconds(&self) -> ::std::option::Option<i64> {
        self.interval_window_in_seconds
    }
}
impl GetInterpolatedAssetPropertyValuesInput {
    /// Creates a new builder-style object to manufacture [`GetInterpolatedAssetPropertyValuesInput`](crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesInput).
    pub fn builder() -> crate::operation::get_interpolated_asset_property_values::builders::GetInterpolatedAssetPropertyValuesInputBuilder {
        crate::operation::get_interpolated_asset_property_values::builders::GetInterpolatedAssetPropertyValuesInputBuilder::default()
    }
}

/// A builder for [`GetInterpolatedAssetPropertyValuesInput`](crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetInterpolatedAssetPropertyValuesInputBuilder {
    pub(crate) asset_id: ::std::option::Option<::std::string::String>,
    pub(crate) property_id: ::std::option::Option<::std::string::String>,
    pub(crate) property_alias: ::std::option::Option<::std::string::String>,
    pub(crate) start_time_in_seconds: ::std::option::Option<i64>,
    pub(crate) start_time_offset_in_nanos: ::std::option::Option<i32>,
    pub(crate) end_time_in_seconds: ::std::option::Option<i64>,
    pub(crate) end_time_offset_in_nanos: ::std::option::Option<i32>,
    pub(crate) quality: ::std::option::Option<crate::types::Quality>,
    pub(crate) interval_in_seconds: ::std::option::Option<i64>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) interval_window_in_seconds: ::std::option::Option<i64>,
}
impl GetInterpolatedAssetPropertyValuesInputBuilder {
    /// <p>The ID of the asset, in UUID format.</p>
    pub fn asset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset, in UUID format.</p>
    pub fn set_asset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_id = input;
        self
    }
    /// <p>The ID of the asset, in UUID format.</p>
    pub fn get_asset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_id
    }
    /// <p>The ID of the asset property, in UUID format.</p>
    pub fn property_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.property_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset property, in UUID format.</p>
    pub fn set_property_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.property_id = input;
        self
    }
    /// <p>The ID of the asset property, in UUID format.</p>
    pub fn get_property_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.property_id
    }
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn property_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.property_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_property_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.property_alias = input;
        self
    }
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_property_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.property_alias
    }
    /// <p>The exclusive start of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    /// This field is required.
    pub fn start_time_in_seconds(mut self, input: i64) -> Self {
        self.start_time_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The exclusive start of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    pub fn set_start_time_in_seconds(mut self, input: ::std::option::Option<i64>) -> Self {
        self.start_time_in_seconds = input;
        self
    }
    /// <p>The exclusive start of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    pub fn get_start_time_in_seconds(&self) -> &::std::option::Option<i64> {
        &self.start_time_in_seconds
    }
    /// <p>The nanosecond offset converted from <code>startTimeInSeconds</code>.</p>
    pub fn start_time_offset_in_nanos(mut self, input: i32) -> Self {
        self.start_time_offset_in_nanos = ::std::option::Option::Some(input);
        self
    }
    /// <p>The nanosecond offset converted from <code>startTimeInSeconds</code>.</p>
    pub fn set_start_time_offset_in_nanos(mut self, input: ::std::option::Option<i32>) -> Self {
        self.start_time_offset_in_nanos = input;
        self
    }
    /// <p>The nanosecond offset converted from <code>startTimeInSeconds</code>.</p>
    pub fn get_start_time_offset_in_nanos(&self) -> &::std::option::Option<i32> {
        &self.start_time_offset_in_nanos
    }
    /// <p>The inclusive end of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    /// This field is required.
    pub fn end_time_in_seconds(mut self, input: i64) -> Self {
        self.end_time_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The inclusive end of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    pub fn set_end_time_in_seconds(mut self, input: ::std::option::Option<i64>) -> Self {
        self.end_time_in_seconds = input;
        self
    }
    /// <p>The inclusive end of the range from which to interpolate data, expressed in seconds in Unix epoch time.</p>
    pub fn get_end_time_in_seconds(&self) -> &::std::option::Option<i64> {
        &self.end_time_in_seconds
    }
    /// <p>The nanosecond offset converted from <code>endTimeInSeconds</code>.</p>
    pub fn end_time_offset_in_nanos(mut self, input: i32) -> Self {
        self.end_time_offset_in_nanos = ::std::option::Option::Some(input);
        self
    }
    /// <p>The nanosecond offset converted from <code>endTimeInSeconds</code>.</p>
    pub fn set_end_time_offset_in_nanos(mut self, input: ::std::option::Option<i32>) -> Self {
        self.end_time_offset_in_nanos = input;
        self
    }
    /// <p>The nanosecond offset converted from <code>endTimeInSeconds</code>.</p>
    pub fn get_end_time_offset_in_nanos(&self) -> &::std::option::Option<i32> {
        &self.end_time_offset_in_nanos
    }
    /// <p>The quality of the asset property value. You can use this parameter as a filter to choose only the asset property values that have a specific quality.</p>
    /// This field is required.
    pub fn quality(mut self, input: crate::types::Quality) -> Self {
        self.quality = ::std::option::Option::Some(input);
        self
    }
    /// <p>The quality of the asset property value. You can use this parameter as a filter to choose only the asset property values that have a specific quality.</p>
    pub fn set_quality(mut self, input: ::std::option::Option<crate::types::Quality>) -> Self {
        self.quality = input;
        self
    }
    /// <p>The quality of the asset property value. You can use this parameter as a filter to choose only the asset property values that have a specific quality.</p>
    pub fn get_quality(&self) -> &::std::option::Option<crate::types::Quality> {
        &self.quality
    }
    /// <p>The time interval in seconds over which to interpolate data. Each interval starts when the previous one ends.</p>
    /// This field is required.
    pub fn interval_in_seconds(mut self, input: i64) -> Self {
        self.interval_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time interval in seconds over which to interpolate data. Each interval starts when the previous one ends.</p>
    pub fn set_interval_in_seconds(mut self, input: ::std::option::Option<i64>) -> Self {
        self.interval_in_seconds = input;
        self
    }
    /// <p>The time interval in seconds over which to interpolate data. Each interval starts when the previous one ends.</p>
    pub fn get_interval_in_seconds(&self) -> &::std::option::Option<i64> {
        &self.interval_in_seconds
    }
    /// <p>The token to be used for the next set of paginated results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to be used for the next set of paginated results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to be used for the next set of paginated results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return for each paginated request. If not specified, the default value is 10.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return for each paginated request. If not specified, the default value is 10.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return for each paginated request. If not specified, the default value is 10.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The interpolation type.</p>
    /// <p>Valid values: <code>LINEAR_INTERPOLATION | LOCF_INTERPOLATION</code></p>
    /// <ul>
    /// <li>
    /// <p><code>LINEAR_INTERPOLATION</code> – Estimates missing data using <a href="https://en.wikipedia.org/wiki/Linear_interpolation">linear interpolation</a>.</p>
    /// <p>For example, you can use this operation to return the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the first interpolated value on July 2, 2021, at 9 AM, the second interpolated value on July 3, 2021, at 9 AM, and so on.</p></li>
    /// <li>
    /// <p><code>LOCF_INTERPOLATION</code> – Estimates missing data using last observation carried forward interpolation</p>
    /// <p>If no data point is found for an interval, IoT SiteWise returns the last observed data point for the previous interval and carries forward this interpolated value until a new data point is found.</p>
    /// <p>For example, you can get the state of an on-off valve every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the last observed data point between July 1, 2021, at 9 AM and July 2, 2021, at 9 AM as the first interpolated value. If a data point isn't found after 9 AM on July 2, 2021, IoT SiteWise uses the same interpolated value for the rest of the days.</p></li>
    /// </ul>
    /// This field is required.
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The interpolation type.</p>
    /// <p>Valid values: <code>LINEAR_INTERPOLATION | LOCF_INTERPOLATION</code></p>
    /// <ul>
    /// <li>
    /// <p><code>LINEAR_INTERPOLATION</code> – Estimates missing data using <a href="https://en.wikipedia.org/wiki/Linear_interpolation">linear interpolation</a>.</p>
    /// <p>For example, you can use this operation to return the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the first interpolated value on July 2, 2021, at 9 AM, the second interpolated value on July 3, 2021, at 9 AM, and so on.</p></li>
    /// <li>
    /// <p><code>LOCF_INTERPOLATION</code> – Estimates missing data using last observation carried forward interpolation</p>
    /// <p>If no data point is found for an interval, IoT SiteWise returns the last observed data point for the previous interval and carries forward this interpolated value until a new data point is found.</p>
    /// <p>For example, you can get the state of an on-off valve every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the last observed data point between July 1, 2021, at 9 AM and July 2, 2021, at 9 AM as the first interpolated value. If a data point isn't found after 9 AM on July 2, 2021, IoT SiteWise uses the same interpolated value for the rest of the days.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The interpolation type.</p>
    /// <p>Valid values: <code>LINEAR_INTERPOLATION | LOCF_INTERPOLATION</code></p>
    /// <ul>
    /// <li>
    /// <p><code>LINEAR_INTERPOLATION</code> – Estimates missing data using <a href="https://en.wikipedia.org/wiki/Linear_interpolation">linear interpolation</a>.</p>
    /// <p>For example, you can use this operation to return the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the first interpolated value on July 2, 2021, at 9 AM, the second interpolated value on July 3, 2021, at 9 AM, and so on.</p></li>
    /// <li>
    /// <p><code>LOCF_INTERPOLATION</code> – Estimates missing data using last observation carried forward interpolation</p>
    /// <p>If no data point is found for an interval, IoT SiteWise returns the last observed data point for the previous interval and carries forward this interpolated value until a new data point is found.</p>
    /// <p>For example, you can get the state of an on-off valve every 24 hours over a duration of 7 days. If the interpolation starts July 1, 2021, at 9 AM, IoT SiteWise returns the last observed data point between July 1, 2021, at 9 AM and July 2, 2021, at 9 AM as the first interpolated value. If a data point isn't found after 9 AM on July 2, 2021, IoT SiteWise uses the same interpolated value for the rest of the days.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The query interval for the window, in seconds. IoT SiteWise computes each interpolated value by using data points from the timestamp of each interval, minus the window to the timestamp of each interval plus the window. If not specified, the window ranges between the start time minus the interval and the end time plus the interval.</p><note>
    /// <ul>
    /// <li>
    /// <p>If you specify a value for the <code>intervalWindowInSeconds</code> parameter, the value for the <code>type</code> parameter must be <code>LINEAR_INTERPOLATION</code>.</p></li>
    /// <li>
    /// <p>If a data point isn't found during the specified query window, IoT SiteWise won't return an interpolated value for the interval. This indicates that there's a gap in the ingested data points.</p></li>
    /// </ul>
    /// </note>
    /// <p>For example, you can get the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts on July 1, 2021, at 9 AM with a window of 2 hours, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 2, 2021 to compute the first interpolated value. Next, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 3, 2021 to compute the second interpolated value, and so on.</p>
    pub fn interval_window_in_seconds(mut self, input: i64) -> Self {
        self.interval_window_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The query interval for the window, in seconds. IoT SiteWise computes each interpolated value by using data points from the timestamp of each interval, minus the window to the timestamp of each interval plus the window. If not specified, the window ranges between the start time minus the interval and the end time plus the interval.</p><note>
    /// <ul>
    /// <li>
    /// <p>If you specify a value for the <code>intervalWindowInSeconds</code> parameter, the value for the <code>type</code> parameter must be <code>LINEAR_INTERPOLATION</code>.</p></li>
    /// <li>
    /// <p>If a data point isn't found during the specified query window, IoT SiteWise won't return an interpolated value for the interval. This indicates that there's a gap in the ingested data points.</p></li>
    /// </ul>
    /// </note>
    /// <p>For example, you can get the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts on July 1, 2021, at 9 AM with a window of 2 hours, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 2, 2021 to compute the first interpolated value. Next, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 3, 2021 to compute the second interpolated value, and so on.</p>
    pub fn set_interval_window_in_seconds(mut self, input: ::std::option::Option<i64>) -> Self {
        self.interval_window_in_seconds = input;
        self
    }
    /// <p>The query interval for the window, in seconds. IoT SiteWise computes each interpolated value by using data points from the timestamp of each interval, minus the window to the timestamp of each interval plus the window. If not specified, the window ranges between the start time minus the interval and the end time plus the interval.</p><note>
    /// <ul>
    /// <li>
    /// <p>If you specify a value for the <code>intervalWindowInSeconds</code> parameter, the value for the <code>type</code> parameter must be <code>LINEAR_INTERPOLATION</code>.</p></li>
    /// <li>
    /// <p>If a data point isn't found during the specified query window, IoT SiteWise won't return an interpolated value for the interval. This indicates that there's a gap in the ingested data points.</p></li>
    /// </ul>
    /// </note>
    /// <p>For example, you can get the interpolated temperature values for a wind turbine every 24 hours over a duration of 7 days. If the interpolation starts on July 1, 2021, at 9 AM with a window of 2 hours, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 2, 2021 to compute the first interpolated value. Next, IoT SiteWise uses the data points from 7 AM (9 AM minus 2 hours) to 11 AM (9 AM plus 2 hours) on July 3, 2021 to compute the second interpolated value, and so on.</p>
    pub fn get_interval_window_in_seconds(&self) -> &::std::option::Option<i64> {
        &self.interval_window_in_seconds
    }
    /// Consumes the builder and constructs a [`GetInterpolatedAssetPropertyValuesInput`](crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesInput {
                asset_id: self.asset_id,
                property_id: self.property_id,
                property_alias: self.property_alias,
                start_time_in_seconds: self.start_time_in_seconds,
                start_time_offset_in_nanos: self.start_time_offset_in_nanos,
                end_time_in_seconds: self.end_time_in_seconds,
                end_time_offset_in_nanos: self.end_time_offset_in_nanos,
                quality: self.quality,
                interval_in_seconds: self.interval_in_seconds,
                next_token: self.next_token,
                max_results: self.max_results,
                r#type: self.r#type,
                interval_window_in_seconds: self.interval_window_in_seconds,
            },
        )
    }
}
