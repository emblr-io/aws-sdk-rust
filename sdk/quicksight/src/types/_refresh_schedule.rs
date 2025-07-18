// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The refresh schedule of a dataset.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RefreshSchedule {
    /// <p>An identifier for the refresh schedule.</p>
    pub schedule_id: ::std::string::String,
    /// <p>The frequency for the refresh schedule.</p>
    pub schedule_frequency: ::std::option::Option<crate::types::RefreshFrequency>,
    /// <p>Time after which the refresh schedule can be started, expressed in <code>YYYY-MM-DDTHH:MM:SS</code> format.</p>
    pub start_after_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The type of refresh that a datset undergoes. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_REFRESH</code>: A complete refresh of a dataset.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_REFRESH</code>: A partial refresh of some rows of a dataset, based on the time window specified.</p></li>
    /// </ul>
    /// <p>For more information on full and incremental refreshes, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/refreshing-imported-data.html">Refreshing SPICE data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub refresh_type: crate::types::IngestionType,
    /// <p>The Amazon Resource Name (ARN) for the refresh schedule.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl RefreshSchedule {
    /// <p>An identifier for the refresh schedule.</p>
    pub fn schedule_id(&self) -> &str {
        use std::ops::Deref;
        self.schedule_id.deref()
    }
    /// <p>The frequency for the refresh schedule.</p>
    pub fn schedule_frequency(&self) -> ::std::option::Option<&crate::types::RefreshFrequency> {
        self.schedule_frequency.as_ref()
    }
    /// <p>Time after which the refresh schedule can be started, expressed in <code>YYYY-MM-DDTHH:MM:SS</code> format.</p>
    pub fn start_after_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_after_date_time.as_ref()
    }
    /// <p>The type of refresh that a datset undergoes. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_REFRESH</code>: A complete refresh of a dataset.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_REFRESH</code>: A partial refresh of some rows of a dataset, based on the time window specified.</p></li>
    /// </ul>
    /// <p>For more information on full and incremental refreshes, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/refreshing-imported-data.html">Refreshing SPICE data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub fn refresh_type(&self) -> &crate::types::IngestionType {
        &self.refresh_type
    }
    /// <p>The Amazon Resource Name (ARN) for the refresh schedule.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl RefreshSchedule {
    /// Creates a new builder-style object to manufacture [`RefreshSchedule`](crate::types::RefreshSchedule).
    pub fn builder() -> crate::types::builders::RefreshScheduleBuilder {
        crate::types::builders::RefreshScheduleBuilder::default()
    }
}

/// A builder for [`RefreshSchedule`](crate::types::RefreshSchedule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RefreshScheduleBuilder {
    pub(crate) schedule_id: ::std::option::Option<::std::string::String>,
    pub(crate) schedule_frequency: ::std::option::Option<crate::types::RefreshFrequency>,
    pub(crate) start_after_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) refresh_type: ::std::option::Option<crate::types::IngestionType>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl RefreshScheduleBuilder {
    /// <p>An identifier for the refresh schedule.</p>
    /// This field is required.
    pub fn schedule_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schedule_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier for the refresh schedule.</p>
    pub fn set_schedule_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schedule_id = input;
        self
    }
    /// <p>An identifier for the refresh schedule.</p>
    pub fn get_schedule_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.schedule_id
    }
    /// <p>The frequency for the refresh schedule.</p>
    /// This field is required.
    pub fn schedule_frequency(mut self, input: crate::types::RefreshFrequency) -> Self {
        self.schedule_frequency = ::std::option::Option::Some(input);
        self
    }
    /// <p>The frequency for the refresh schedule.</p>
    pub fn set_schedule_frequency(mut self, input: ::std::option::Option<crate::types::RefreshFrequency>) -> Self {
        self.schedule_frequency = input;
        self
    }
    /// <p>The frequency for the refresh schedule.</p>
    pub fn get_schedule_frequency(&self) -> &::std::option::Option<crate::types::RefreshFrequency> {
        &self.schedule_frequency
    }
    /// <p>Time after which the refresh schedule can be started, expressed in <code>YYYY-MM-DDTHH:MM:SS</code> format.</p>
    pub fn start_after_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_after_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time after which the refresh schedule can be started, expressed in <code>YYYY-MM-DDTHH:MM:SS</code> format.</p>
    pub fn set_start_after_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_after_date_time = input;
        self
    }
    /// <p>Time after which the refresh schedule can be started, expressed in <code>YYYY-MM-DDTHH:MM:SS</code> format.</p>
    pub fn get_start_after_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_after_date_time
    }
    /// <p>The type of refresh that a datset undergoes. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_REFRESH</code>: A complete refresh of a dataset.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_REFRESH</code>: A partial refresh of some rows of a dataset, based on the time window specified.</p></li>
    /// </ul>
    /// <p>For more information on full and incremental refreshes, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/refreshing-imported-data.html">Refreshing SPICE data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    /// This field is required.
    pub fn refresh_type(mut self, input: crate::types::IngestionType) -> Self {
        self.refresh_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of refresh that a datset undergoes. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_REFRESH</code>: A complete refresh of a dataset.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_REFRESH</code>: A partial refresh of some rows of a dataset, based on the time window specified.</p></li>
    /// </ul>
    /// <p>For more information on full and incremental refreshes, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/refreshing-imported-data.html">Refreshing SPICE data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub fn set_refresh_type(mut self, input: ::std::option::Option<crate::types::IngestionType>) -> Self {
        self.refresh_type = input;
        self
    }
    /// <p>The type of refresh that a datset undergoes. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_REFRESH</code>: A complete refresh of a dataset.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_REFRESH</code>: A partial refresh of some rows of a dataset, based on the time window specified.</p></li>
    /// </ul>
    /// <p>For more information on full and incremental refreshes, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/refreshing-imported-data.html">Refreshing SPICE data</a> in the <i>Amazon QuickSight User Guide</i>.</p>
    pub fn get_refresh_type(&self) -> &::std::option::Option<crate::types::IngestionType> {
        &self.refresh_type
    }
    /// <p>The Amazon Resource Name (ARN) for the refresh schedule.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the refresh schedule.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the refresh schedule.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`RefreshSchedule`](crate::types::RefreshSchedule).
    /// This method will fail if any of the following fields are not set:
    /// - [`schedule_id`](crate::types::builders::RefreshScheduleBuilder::schedule_id)
    /// - [`refresh_type`](crate::types::builders::RefreshScheduleBuilder::refresh_type)
    pub fn build(self) -> ::std::result::Result<crate::types::RefreshSchedule, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RefreshSchedule {
            schedule_id: self.schedule_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "schedule_id",
                    "schedule_id was not specified but it is required when building RefreshSchedule",
                )
            })?,
            schedule_frequency: self.schedule_frequency,
            start_after_date_time: self.start_after_date_time,
            refresh_type: self.refresh_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "refresh_type",
                    "refresh_type was not specified but it is required when building RefreshSchedule",
                )
            })?,
            arn: self.arn,
        })
    }
}
