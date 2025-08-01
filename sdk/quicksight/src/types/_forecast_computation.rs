// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The forecast computation configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ForecastComputation {
    /// <p>The ID for a computation.</p>
    pub computation_id: ::std::string::String,
    /// <p>The name of a computation.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The time field that is used in a computation.</p>
    pub time: ::std::option::Option<crate::types::DimensionField>,
    /// <p>The value field that is used in a computation.</p>
    pub value: ::std::option::Option<crate::types::MeasureField>,
    /// <p>The periods forward setup of a forecast computation.</p>
    pub periods_forward: ::std::option::Option<i32>,
    /// <p>The periods backward setup of a forecast computation.</p>
    pub periods_backward: ::std::option::Option<i32>,
    /// <p>The upper boundary setup of a forecast computation.</p>
    pub upper_boundary: ::std::option::Option<f64>,
    /// <p>The lower boundary setup of a forecast computation.</p>
    pub lower_boundary: ::std::option::Option<f64>,
    /// <p>The prediction interval setup of a forecast computation.</p>
    pub prediction_interval: ::std::option::Option<i32>,
    /// <p>The seasonality setup of a forecast computation. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>AUTOMATIC</code></p></li>
    /// <li>
    /// <p><code>CUSTOM</code>: Checks the custom seasonality value.</p></li>
    /// </ul>
    pub seasonality: ::std::option::Option<crate::types::ForecastComputationSeasonality>,
    /// <p>The custom seasonality value setup of a forecast computation.</p>
    pub custom_seasonality_value: ::std::option::Option<i32>,
}
impl ForecastComputation {
    /// <p>The ID for a computation.</p>
    pub fn computation_id(&self) -> &str {
        use std::ops::Deref;
        self.computation_id.deref()
    }
    /// <p>The name of a computation.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The time field that is used in a computation.</p>
    pub fn time(&self) -> ::std::option::Option<&crate::types::DimensionField> {
        self.time.as_ref()
    }
    /// <p>The value field that is used in a computation.</p>
    pub fn value(&self) -> ::std::option::Option<&crate::types::MeasureField> {
        self.value.as_ref()
    }
    /// <p>The periods forward setup of a forecast computation.</p>
    pub fn periods_forward(&self) -> ::std::option::Option<i32> {
        self.periods_forward
    }
    /// <p>The periods backward setup of a forecast computation.</p>
    pub fn periods_backward(&self) -> ::std::option::Option<i32> {
        self.periods_backward
    }
    /// <p>The upper boundary setup of a forecast computation.</p>
    pub fn upper_boundary(&self) -> ::std::option::Option<f64> {
        self.upper_boundary
    }
    /// <p>The lower boundary setup of a forecast computation.</p>
    pub fn lower_boundary(&self) -> ::std::option::Option<f64> {
        self.lower_boundary
    }
    /// <p>The prediction interval setup of a forecast computation.</p>
    pub fn prediction_interval(&self) -> ::std::option::Option<i32> {
        self.prediction_interval
    }
    /// <p>The seasonality setup of a forecast computation. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>AUTOMATIC</code></p></li>
    /// <li>
    /// <p><code>CUSTOM</code>: Checks the custom seasonality value.</p></li>
    /// </ul>
    pub fn seasonality(&self) -> ::std::option::Option<&crate::types::ForecastComputationSeasonality> {
        self.seasonality.as_ref()
    }
    /// <p>The custom seasonality value setup of a forecast computation.</p>
    pub fn custom_seasonality_value(&self) -> ::std::option::Option<i32> {
        self.custom_seasonality_value
    }
}
impl ForecastComputation {
    /// Creates a new builder-style object to manufacture [`ForecastComputation`](crate::types::ForecastComputation).
    pub fn builder() -> crate::types::builders::ForecastComputationBuilder {
        crate::types::builders::ForecastComputationBuilder::default()
    }
}

/// A builder for [`ForecastComputation`](crate::types::ForecastComputation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ForecastComputationBuilder {
    pub(crate) computation_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) time: ::std::option::Option<crate::types::DimensionField>,
    pub(crate) value: ::std::option::Option<crate::types::MeasureField>,
    pub(crate) periods_forward: ::std::option::Option<i32>,
    pub(crate) periods_backward: ::std::option::Option<i32>,
    pub(crate) upper_boundary: ::std::option::Option<f64>,
    pub(crate) lower_boundary: ::std::option::Option<f64>,
    pub(crate) prediction_interval: ::std::option::Option<i32>,
    pub(crate) seasonality: ::std::option::Option<crate::types::ForecastComputationSeasonality>,
    pub(crate) custom_seasonality_value: ::std::option::Option<i32>,
}
impl ForecastComputationBuilder {
    /// <p>The ID for a computation.</p>
    /// This field is required.
    pub fn computation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.computation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for a computation.</p>
    pub fn set_computation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.computation_id = input;
        self
    }
    /// <p>The ID for a computation.</p>
    pub fn get_computation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.computation_id
    }
    /// <p>The name of a computation.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a computation.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of a computation.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The time field that is used in a computation.</p>
    pub fn time(mut self, input: crate::types::DimensionField) -> Self {
        self.time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time field that is used in a computation.</p>
    pub fn set_time(mut self, input: ::std::option::Option<crate::types::DimensionField>) -> Self {
        self.time = input;
        self
    }
    /// <p>The time field that is used in a computation.</p>
    pub fn get_time(&self) -> &::std::option::Option<crate::types::DimensionField> {
        &self.time
    }
    /// <p>The value field that is used in a computation.</p>
    pub fn value(mut self, input: crate::types::MeasureField) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value field that is used in a computation.</p>
    pub fn set_value(mut self, input: ::std::option::Option<crate::types::MeasureField>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value field that is used in a computation.</p>
    pub fn get_value(&self) -> &::std::option::Option<crate::types::MeasureField> {
        &self.value
    }
    /// <p>The periods forward setup of a forecast computation.</p>
    pub fn periods_forward(mut self, input: i32) -> Self {
        self.periods_forward = ::std::option::Option::Some(input);
        self
    }
    /// <p>The periods forward setup of a forecast computation.</p>
    pub fn set_periods_forward(mut self, input: ::std::option::Option<i32>) -> Self {
        self.periods_forward = input;
        self
    }
    /// <p>The periods forward setup of a forecast computation.</p>
    pub fn get_periods_forward(&self) -> &::std::option::Option<i32> {
        &self.periods_forward
    }
    /// <p>The periods backward setup of a forecast computation.</p>
    pub fn periods_backward(mut self, input: i32) -> Self {
        self.periods_backward = ::std::option::Option::Some(input);
        self
    }
    /// <p>The periods backward setup of a forecast computation.</p>
    pub fn set_periods_backward(mut self, input: ::std::option::Option<i32>) -> Self {
        self.periods_backward = input;
        self
    }
    /// <p>The periods backward setup of a forecast computation.</p>
    pub fn get_periods_backward(&self) -> &::std::option::Option<i32> {
        &self.periods_backward
    }
    /// <p>The upper boundary setup of a forecast computation.</p>
    pub fn upper_boundary(mut self, input: f64) -> Self {
        self.upper_boundary = ::std::option::Option::Some(input);
        self
    }
    /// <p>The upper boundary setup of a forecast computation.</p>
    pub fn set_upper_boundary(mut self, input: ::std::option::Option<f64>) -> Self {
        self.upper_boundary = input;
        self
    }
    /// <p>The upper boundary setup of a forecast computation.</p>
    pub fn get_upper_boundary(&self) -> &::std::option::Option<f64> {
        &self.upper_boundary
    }
    /// <p>The lower boundary setup of a forecast computation.</p>
    pub fn lower_boundary(mut self, input: f64) -> Self {
        self.lower_boundary = ::std::option::Option::Some(input);
        self
    }
    /// <p>The lower boundary setup of a forecast computation.</p>
    pub fn set_lower_boundary(mut self, input: ::std::option::Option<f64>) -> Self {
        self.lower_boundary = input;
        self
    }
    /// <p>The lower boundary setup of a forecast computation.</p>
    pub fn get_lower_boundary(&self) -> &::std::option::Option<f64> {
        &self.lower_boundary
    }
    /// <p>The prediction interval setup of a forecast computation.</p>
    pub fn prediction_interval(mut self, input: i32) -> Self {
        self.prediction_interval = ::std::option::Option::Some(input);
        self
    }
    /// <p>The prediction interval setup of a forecast computation.</p>
    pub fn set_prediction_interval(mut self, input: ::std::option::Option<i32>) -> Self {
        self.prediction_interval = input;
        self
    }
    /// <p>The prediction interval setup of a forecast computation.</p>
    pub fn get_prediction_interval(&self) -> &::std::option::Option<i32> {
        &self.prediction_interval
    }
    /// <p>The seasonality setup of a forecast computation. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>AUTOMATIC</code></p></li>
    /// <li>
    /// <p><code>CUSTOM</code>: Checks the custom seasonality value.</p></li>
    /// </ul>
    pub fn seasonality(mut self, input: crate::types::ForecastComputationSeasonality) -> Self {
        self.seasonality = ::std::option::Option::Some(input);
        self
    }
    /// <p>The seasonality setup of a forecast computation. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>AUTOMATIC</code></p></li>
    /// <li>
    /// <p><code>CUSTOM</code>: Checks the custom seasonality value.</p></li>
    /// </ul>
    pub fn set_seasonality(mut self, input: ::std::option::Option<crate::types::ForecastComputationSeasonality>) -> Self {
        self.seasonality = input;
        self
    }
    /// <p>The seasonality setup of a forecast computation. Choose one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>AUTOMATIC</code></p></li>
    /// <li>
    /// <p><code>CUSTOM</code>: Checks the custom seasonality value.</p></li>
    /// </ul>
    pub fn get_seasonality(&self) -> &::std::option::Option<crate::types::ForecastComputationSeasonality> {
        &self.seasonality
    }
    /// <p>The custom seasonality value setup of a forecast computation.</p>
    pub fn custom_seasonality_value(mut self, input: i32) -> Self {
        self.custom_seasonality_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The custom seasonality value setup of a forecast computation.</p>
    pub fn set_custom_seasonality_value(mut self, input: ::std::option::Option<i32>) -> Self {
        self.custom_seasonality_value = input;
        self
    }
    /// <p>The custom seasonality value setup of a forecast computation.</p>
    pub fn get_custom_seasonality_value(&self) -> &::std::option::Option<i32> {
        &self.custom_seasonality_value
    }
    /// Consumes the builder and constructs a [`ForecastComputation`](crate::types::ForecastComputation).
    /// This method will fail if any of the following fields are not set:
    /// - [`computation_id`](crate::types::builders::ForecastComputationBuilder::computation_id)
    pub fn build(self) -> ::std::result::Result<crate::types::ForecastComputation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ForecastComputation {
            computation_id: self.computation_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "computation_id",
                    "computation_id was not specified but it is required when building ForecastComputation",
                )
            })?,
            name: self.name,
            time: self.time,
            value: self.value,
            periods_forward: self.periods_forward,
            periods_backward: self.periods_backward,
            upper_boundary: self.upper_boundary,
            lower_boundary: self.lower_boundary,
            prediction_interval: self.prediction_interval,
            seasonality: self.seasonality,
            custom_seasonality_value: self.custom_seasonality_value,
        })
    }
}
