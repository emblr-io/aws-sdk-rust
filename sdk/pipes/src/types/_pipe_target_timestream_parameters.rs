// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for using a Timestream for LiveAnalytics table as a target.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PipeTargetTimestreamParameters {
    /// <p>Dynamic path to the source data field that represents the time value for your data.</p>
    pub time_value: ::std::string::String,
    /// <p>The granularity of the time units used. Default is <code>MILLISECONDS</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.</p>
    pub epoch_time_unit: ::std::option::Option<crate::types::EpochTimeUnit>,
    /// <p>The type of time value used.</p>
    /// <p>The default is <code>EPOCH</code>.</p>
    pub time_field_type: ::std::option::Option<crate::types::TimeFieldType>,
    /// <p>How to format the timestamps. For example, <code>yyyy-MM-dd'T'HH:mm:ss'Z'</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.</p>
    pub timestamp_format: ::std::option::Option<::std::string::String>,
    /// <p>64 bit version value or source data field that represents the version value for your data.</p>
    /// <p>Write requests with a higher version number will update the existing measure values of the record and version. In cases where the measure value is the same, the version will still be updated.</p>
    /// <p>Default value is 1.</p>
    /// <p>Timestream for LiveAnalytics does not support updating partial measure values in a record.</p>
    /// <p>Write requests for duplicate data with a higher version number will update the existing measure value and version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default value is <code>1</code>.</p><note>
    /// <p><code>Version</code> must be <code>1</code> or greater, or you will receive a <code>ValidationException</code> error.</p>
    /// </note>
    pub version_value: ::std::string::String,
    /// <p>Map source data to dimensions in the target Timestream for LiveAnalytics table.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for LiveAnalytics concepts</a></p>
    pub dimension_mappings: ::std::vec::Vec<crate::types::DimensionMapping>,
    /// <p>Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.</p>
    pub single_measure_mappings: ::std::option::Option<::std::vec::Vec<crate::types::SingleMeasureMapping>>,
    /// <p>Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics table.</p>
    pub multi_measure_mappings: ::std::option::Option<::std::vec::Vec<crate::types::MultiMeasureMapping>>,
}
impl PipeTargetTimestreamParameters {
    /// <p>Dynamic path to the source data field that represents the time value for your data.</p>
    pub fn time_value(&self) -> &str {
        use std::ops::Deref;
        self.time_value.deref()
    }
    /// <p>The granularity of the time units used. Default is <code>MILLISECONDS</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.</p>
    pub fn epoch_time_unit(&self) -> ::std::option::Option<&crate::types::EpochTimeUnit> {
        self.epoch_time_unit.as_ref()
    }
    /// <p>The type of time value used.</p>
    /// <p>The default is <code>EPOCH</code>.</p>
    pub fn time_field_type(&self) -> ::std::option::Option<&crate::types::TimeFieldType> {
        self.time_field_type.as_ref()
    }
    /// <p>How to format the timestamps. For example, <code>yyyy-MM-dd'T'HH:mm:ss'Z'</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.</p>
    pub fn timestamp_format(&self) -> ::std::option::Option<&str> {
        self.timestamp_format.as_deref()
    }
    /// <p>64 bit version value or source data field that represents the version value for your data.</p>
    /// <p>Write requests with a higher version number will update the existing measure values of the record and version. In cases where the measure value is the same, the version will still be updated.</p>
    /// <p>Default value is 1.</p>
    /// <p>Timestream for LiveAnalytics does not support updating partial measure values in a record.</p>
    /// <p>Write requests for duplicate data with a higher version number will update the existing measure value and version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default value is <code>1</code>.</p><note>
    /// <p><code>Version</code> must be <code>1</code> or greater, or you will receive a <code>ValidationException</code> error.</p>
    /// </note>
    pub fn version_value(&self) -> &str {
        use std::ops::Deref;
        self.version_value.deref()
    }
    /// <p>Map source data to dimensions in the target Timestream for LiveAnalytics table.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for LiveAnalytics concepts</a></p>
    pub fn dimension_mappings(&self) -> &[crate::types::DimensionMapping] {
        use std::ops::Deref;
        self.dimension_mappings.deref()
    }
    /// <p>Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.single_measure_mappings.is_none()`.
    pub fn single_measure_mappings(&self) -> &[crate::types::SingleMeasureMapping] {
        self.single_measure_mappings.as_deref().unwrap_or_default()
    }
    /// <p>Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics table.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.multi_measure_mappings.is_none()`.
    pub fn multi_measure_mappings(&self) -> &[crate::types::MultiMeasureMapping] {
        self.multi_measure_mappings.as_deref().unwrap_or_default()
    }
}
impl PipeTargetTimestreamParameters {
    /// Creates a new builder-style object to manufacture [`PipeTargetTimestreamParameters`](crate::types::PipeTargetTimestreamParameters).
    pub fn builder() -> crate::types::builders::PipeTargetTimestreamParametersBuilder {
        crate::types::builders::PipeTargetTimestreamParametersBuilder::default()
    }
}

/// A builder for [`PipeTargetTimestreamParameters`](crate::types::PipeTargetTimestreamParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PipeTargetTimestreamParametersBuilder {
    pub(crate) time_value: ::std::option::Option<::std::string::String>,
    pub(crate) epoch_time_unit: ::std::option::Option<crate::types::EpochTimeUnit>,
    pub(crate) time_field_type: ::std::option::Option<crate::types::TimeFieldType>,
    pub(crate) timestamp_format: ::std::option::Option<::std::string::String>,
    pub(crate) version_value: ::std::option::Option<::std::string::String>,
    pub(crate) dimension_mappings: ::std::option::Option<::std::vec::Vec<crate::types::DimensionMapping>>,
    pub(crate) single_measure_mappings: ::std::option::Option<::std::vec::Vec<crate::types::SingleMeasureMapping>>,
    pub(crate) multi_measure_mappings: ::std::option::Option<::std::vec::Vec<crate::types::MultiMeasureMapping>>,
}
impl PipeTargetTimestreamParametersBuilder {
    /// <p>Dynamic path to the source data field that represents the time value for your data.</p>
    /// This field is required.
    pub fn time_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.time_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Dynamic path to the source data field that represents the time value for your data.</p>
    pub fn set_time_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.time_value = input;
        self
    }
    /// <p>Dynamic path to the source data field that represents the time value for your data.</p>
    pub fn get_time_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.time_value
    }
    /// <p>The granularity of the time units used. Default is <code>MILLISECONDS</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.</p>
    pub fn epoch_time_unit(mut self, input: crate::types::EpochTimeUnit) -> Self {
        self.epoch_time_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The granularity of the time units used. Default is <code>MILLISECONDS</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.</p>
    pub fn set_epoch_time_unit(mut self, input: ::std::option::Option<crate::types::EpochTimeUnit>) -> Self {
        self.epoch_time_unit = input;
        self
    }
    /// <p>The granularity of the time units used. Default is <code>MILLISECONDS</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>EPOCH</code>.</p>
    pub fn get_epoch_time_unit(&self) -> &::std::option::Option<crate::types::EpochTimeUnit> {
        &self.epoch_time_unit
    }
    /// <p>The type of time value used.</p>
    /// <p>The default is <code>EPOCH</code>.</p>
    pub fn time_field_type(mut self, input: crate::types::TimeFieldType) -> Self {
        self.time_field_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of time value used.</p>
    /// <p>The default is <code>EPOCH</code>.</p>
    pub fn set_time_field_type(mut self, input: ::std::option::Option<crate::types::TimeFieldType>) -> Self {
        self.time_field_type = input;
        self
    }
    /// <p>The type of time value used.</p>
    /// <p>The default is <code>EPOCH</code>.</p>
    pub fn get_time_field_type(&self) -> &::std::option::Option<crate::types::TimeFieldType> {
        &self.time_field_type
    }
    /// <p>How to format the timestamps. For example, <code>yyyy-MM-dd'T'HH:mm:ss'Z'</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.</p>
    pub fn timestamp_format(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timestamp_format = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>How to format the timestamps. For example, <code>yyyy-MM-dd'T'HH:mm:ss'Z'</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.</p>
    pub fn set_timestamp_format(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timestamp_format = input;
        self
    }
    /// <p>How to format the timestamps. For example, <code>yyyy-MM-dd'T'HH:mm:ss'Z'</code>.</p>
    /// <p>Required if <code>TimeFieldType</code> is specified as <code>TIMESTAMP_FORMAT</code>.</p>
    pub fn get_timestamp_format(&self) -> &::std::option::Option<::std::string::String> {
        &self.timestamp_format
    }
    /// <p>64 bit version value or source data field that represents the version value for your data.</p>
    /// <p>Write requests with a higher version number will update the existing measure values of the record and version. In cases where the measure value is the same, the version will still be updated.</p>
    /// <p>Default value is 1.</p>
    /// <p>Timestream for LiveAnalytics does not support updating partial measure values in a record.</p>
    /// <p>Write requests for duplicate data with a higher version number will update the existing measure value and version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default value is <code>1</code>.</p><note>
    /// <p><code>Version</code> must be <code>1</code> or greater, or you will receive a <code>ValidationException</code> error.</p>
    /// </note>
    /// This field is required.
    pub fn version_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>64 bit version value or source data field that represents the version value for your data.</p>
    /// <p>Write requests with a higher version number will update the existing measure values of the record and version. In cases where the measure value is the same, the version will still be updated.</p>
    /// <p>Default value is 1.</p>
    /// <p>Timestream for LiveAnalytics does not support updating partial measure values in a record.</p>
    /// <p>Write requests for duplicate data with a higher version number will update the existing measure value and version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default value is <code>1</code>.</p><note>
    /// <p><code>Version</code> must be <code>1</code> or greater, or you will receive a <code>ValidationException</code> error.</p>
    /// </note>
    pub fn set_version_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_value = input;
        self
    }
    /// <p>64 bit version value or source data field that represents the version value for your data.</p>
    /// <p>Write requests with a higher version number will update the existing measure values of the record and version. In cases where the measure value is the same, the version will still be updated.</p>
    /// <p>Default value is 1.</p>
    /// <p>Timestream for LiveAnalytics does not support updating partial measure values in a record.</p>
    /// <p>Write requests for duplicate data with a higher version number will update the existing measure value and version. In cases where the measure value is the same, <code>Version</code> will still be updated. Default value is <code>1</code>.</p><note>
    /// <p><code>Version</code> must be <code>1</code> or greater, or you will receive a <code>ValidationException</code> error.</p>
    /// </note>
    pub fn get_version_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_value
    }
    /// Appends an item to `dimension_mappings`.
    ///
    /// To override the contents of this collection use [`set_dimension_mappings`](Self::set_dimension_mappings).
    ///
    /// <p>Map source data to dimensions in the target Timestream for LiveAnalytics table.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for LiveAnalytics concepts</a></p>
    pub fn dimension_mappings(mut self, input: crate::types::DimensionMapping) -> Self {
        let mut v = self.dimension_mappings.unwrap_or_default();
        v.push(input);
        self.dimension_mappings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Map source data to dimensions in the target Timestream for LiveAnalytics table.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for LiveAnalytics concepts</a></p>
    pub fn set_dimension_mappings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DimensionMapping>>) -> Self {
        self.dimension_mappings = input;
        self
    }
    /// <p>Map source data to dimensions in the target Timestream for LiveAnalytics table.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/timestream/latest/developerguide/concepts.html">Amazon Timestream for LiveAnalytics concepts</a></p>
    pub fn get_dimension_mappings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DimensionMapping>> {
        &self.dimension_mappings
    }
    /// Appends an item to `single_measure_mappings`.
    ///
    /// To override the contents of this collection use [`set_single_measure_mappings`](Self::set_single_measure_mappings).
    ///
    /// <p>Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.</p>
    pub fn single_measure_mappings(mut self, input: crate::types::SingleMeasureMapping) -> Self {
        let mut v = self.single_measure_mappings.unwrap_or_default();
        v.push(input);
        self.single_measure_mappings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.</p>
    pub fn set_single_measure_mappings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SingleMeasureMapping>>) -> Self {
        self.single_measure_mappings = input;
        self
    }
    /// <p>Mappings of single source data fields to individual records in the specified Timestream for LiveAnalytics table.</p>
    pub fn get_single_measure_mappings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SingleMeasureMapping>> {
        &self.single_measure_mappings
    }
    /// Appends an item to `multi_measure_mappings`.
    ///
    /// To override the contents of this collection use [`set_multi_measure_mappings`](Self::set_multi_measure_mappings).
    ///
    /// <p>Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics table.</p>
    pub fn multi_measure_mappings(mut self, input: crate::types::MultiMeasureMapping) -> Self {
        let mut v = self.multi_measure_mappings.unwrap_or_default();
        v.push(input);
        self.multi_measure_mappings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics table.</p>
    pub fn set_multi_measure_mappings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MultiMeasureMapping>>) -> Self {
        self.multi_measure_mappings = input;
        self
    }
    /// <p>Maps multiple measures from the source event to the same record in the specified Timestream for LiveAnalytics table.</p>
    pub fn get_multi_measure_mappings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MultiMeasureMapping>> {
        &self.multi_measure_mappings
    }
    /// Consumes the builder and constructs a [`PipeTargetTimestreamParameters`](crate::types::PipeTargetTimestreamParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`time_value`](crate::types::builders::PipeTargetTimestreamParametersBuilder::time_value)
    /// - [`version_value`](crate::types::builders::PipeTargetTimestreamParametersBuilder::version_value)
    /// - [`dimension_mappings`](crate::types::builders::PipeTargetTimestreamParametersBuilder::dimension_mappings)
    pub fn build(self) -> ::std::result::Result<crate::types::PipeTargetTimestreamParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PipeTargetTimestreamParameters {
            time_value: self.time_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "time_value",
                    "time_value was not specified but it is required when building PipeTargetTimestreamParameters",
                )
            })?,
            epoch_time_unit: self.epoch_time_unit,
            time_field_type: self.time_field_type,
            timestamp_format: self.timestamp_format,
            version_value: self.version_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "version_value",
                    "version_value was not specified but it is required when building PipeTargetTimestreamParameters",
                )
            })?,
            dimension_mappings: self.dimension_mappings.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dimension_mappings",
                    "dimension_mappings was not specified but it is required when building PipeTargetTimestreamParameters",
                )
            })?,
            single_measure_mappings: self.single_measure_mappings,
            multi_measure_mappings: self.multi_measure_mappings,
        })
    }
}
