// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A <code>GetPredictiveScalingForecast</code> call returns the capacity forecast for a predictive scaling policy. This structure includes the data points for that capacity forecast, along with the timestamps of those data points.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CapacityForecast {
    /// <p>The timestamps for the data points, in UTC format.</p>
    pub timestamps: ::std::vec::Vec<::aws_smithy_types::DateTime>,
    /// <p>The values of the data points.</p>
    pub values: ::std::vec::Vec<f64>,
}
impl CapacityForecast {
    /// <p>The timestamps for the data points, in UTC format.</p>
    pub fn timestamps(&self) -> &[::aws_smithy_types::DateTime] {
        use std::ops::Deref;
        self.timestamps.deref()
    }
    /// <p>The values of the data points.</p>
    pub fn values(&self) -> &[f64] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl CapacityForecast {
    /// Creates a new builder-style object to manufacture [`CapacityForecast`](crate::types::CapacityForecast).
    pub fn builder() -> crate::types::builders::CapacityForecastBuilder {
        crate::types::builders::CapacityForecastBuilder::default()
    }
}

/// A builder for [`CapacityForecast`](crate::types::CapacityForecast).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CapacityForecastBuilder {
    pub(crate) timestamps: ::std::option::Option<::std::vec::Vec<::aws_smithy_types::DateTime>>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<f64>>,
}
impl CapacityForecastBuilder {
    /// Appends an item to `timestamps`.
    ///
    /// To override the contents of this collection use [`set_timestamps`](Self::set_timestamps).
    ///
    /// <p>The timestamps for the data points, in UTC format.</p>
    pub fn timestamps(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        let mut v = self.timestamps.unwrap_or_default();
        v.push(input);
        self.timestamps = ::std::option::Option::Some(v);
        self
    }
    /// <p>The timestamps for the data points, in UTC format.</p>
    pub fn set_timestamps(mut self, input: ::std::option::Option<::std::vec::Vec<::aws_smithy_types::DateTime>>) -> Self {
        self.timestamps = input;
        self
    }
    /// <p>The timestamps for the data points, in UTC format.</p>
    pub fn get_timestamps(&self) -> &::std::option::Option<::std::vec::Vec<::aws_smithy_types::DateTime>> {
        &self.timestamps
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The values of the data points.</p>
    pub fn values(mut self, input: f64) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input);
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The values of the data points.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The values of the data points.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`CapacityForecast`](crate::types::CapacityForecast).
    /// This method will fail if any of the following fields are not set:
    /// - [`timestamps`](crate::types::builders::CapacityForecastBuilder::timestamps)
    /// - [`values`](crate::types::builders::CapacityForecastBuilder::values)
    pub fn build(self) -> ::std::result::Result<crate::types::CapacityForecast, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CapacityForecast {
            timestamps: self.timestamps.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "timestamps",
                    "timestamps was not specified but it is required when building CapacityForecast",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building CapacityForecast",
                )
            })?,
        })
    }
}
