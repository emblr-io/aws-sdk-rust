// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ForecastGeofenceEventsOutput {
    /// <p>The list of forecasted events.</p>
    pub forecasted_events: ::std::vec::Vec<crate::types::ForecastedEvent>,
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The distance unit for the forecasted events.</p>
    pub distance_unit: crate::types::DistanceUnit,
    /// <p>The speed unit for the forecasted events.</p>
    pub speed_unit: crate::types::SpeedUnit,
    _request_id: Option<String>,
}
impl ForecastGeofenceEventsOutput {
    /// <p>The list of forecasted events.</p>
    pub fn forecasted_events(&self) -> &[crate::types::ForecastedEvent] {
        use std::ops::Deref;
        self.forecasted_events.deref()
    }
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The distance unit for the forecasted events.</p>
    pub fn distance_unit(&self) -> &crate::types::DistanceUnit {
        &self.distance_unit
    }
    /// <p>The speed unit for the forecasted events.</p>
    pub fn speed_unit(&self) -> &crate::types::SpeedUnit {
        &self.speed_unit
    }
}
impl ::aws_types::request_id::RequestId for ForecastGeofenceEventsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ForecastGeofenceEventsOutput {
    /// Creates a new builder-style object to manufacture [`ForecastGeofenceEventsOutput`](crate::operation::forecast_geofence_events::ForecastGeofenceEventsOutput).
    pub fn builder() -> crate::operation::forecast_geofence_events::builders::ForecastGeofenceEventsOutputBuilder {
        crate::operation::forecast_geofence_events::builders::ForecastGeofenceEventsOutputBuilder::default()
    }
}

/// A builder for [`ForecastGeofenceEventsOutput`](crate::operation::forecast_geofence_events::ForecastGeofenceEventsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ForecastGeofenceEventsOutputBuilder {
    pub(crate) forecasted_events: ::std::option::Option<::std::vec::Vec<crate::types::ForecastedEvent>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) distance_unit: ::std::option::Option<crate::types::DistanceUnit>,
    pub(crate) speed_unit: ::std::option::Option<crate::types::SpeedUnit>,
    _request_id: Option<String>,
}
impl ForecastGeofenceEventsOutputBuilder {
    /// Appends an item to `forecasted_events`.
    ///
    /// To override the contents of this collection use [`set_forecasted_events`](Self::set_forecasted_events).
    ///
    /// <p>The list of forecasted events.</p>
    pub fn forecasted_events(mut self, input: crate::types::ForecastedEvent) -> Self {
        let mut v = self.forecasted_events.unwrap_or_default();
        v.push(input);
        self.forecasted_events = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of forecasted events.</p>
    pub fn set_forecasted_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ForecastedEvent>>) -> Self {
        self.forecasted_events = input;
        self
    }
    /// <p>The list of forecasted events.</p>
    pub fn get_forecasted_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ForecastedEvent>> {
        &self.forecasted_events
    }
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The distance unit for the forecasted events.</p>
    /// This field is required.
    pub fn distance_unit(mut self, input: crate::types::DistanceUnit) -> Self {
        self.distance_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The distance unit for the forecasted events.</p>
    pub fn set_distance_unit(mut self, input: ::std::option::Option<crate::types::DistanceUnit>) -> Self {
        self.distance_unit = input;
        self
    }
    /// <p>The distance unit for the forecasted events.</p>
    pub fn get_distance_unit(&self) -> &::std::option::Option<crate::types::DistanceUnit> {
        &self.distance_unit
    }
    /// <p>The speed unit for the forecasted events.</p>
    /// This field is required.
    pub fn speed_unit(mut self, input: crate::types::SpeedUnit) -> Self {
        self.speed_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The speed unit for the forecasted events.</p>
    pub fn set_speed_unit(mut self, input: ::std::option::Option<crate::types::SpeedUnit>) -> Self {
        self.speed_unit = input;
        self
    }
    /// <p>The speed unit for the forecasted events.</p>
    pub fn get_speed_unit(&self) -> &::std::option::Option<crate::types::SpeedUnit> {
        &self.speed_unit
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ForecastGeofenceEventsOutput`](crate::operation::forecast_geofence_events::ForecastGeofenceEventsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`forecasted_events`](crate::operation::forecast_geofence_events::builders::ForecastGeofenceEventsOutputBuilder::forecasted_events)
    /// - [`distance_unit`](crate::operation::forecast_geofence_events::builders::ForecastGeofenceEventsOutputBuilder::distance_unit)
    /// - [`speed_unit`](crate::operation::forecast_geofence_events::builders::ForecastGeofenceEventsOutputBuilder::speed_unit)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::forecast_geofence_events::ForecastGeofenceEventsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::forecast_geofence_events::ForecastGeofenceEventsOutput {
            forecasted_events: self.forecasted_events.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "forecasted_events",
                    "forecasted_events was not specified but it is required when building ForecastGeofenceEventsOutput",
                )
            })?,
            next_token: self.next_token,
            distance_unit: self.distance_unit.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "distance_unit",
                    "distance_unit was not specified but it is required when building ForecastGeofenceEventsOutput",
                )
            })?,
            speed_unit: self.speed_unit.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "speed_unit",
                    "speed_unit was not specified but it is required when building ForecastGeofenceEventsOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
