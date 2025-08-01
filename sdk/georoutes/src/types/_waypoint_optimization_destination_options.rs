// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Destination related options.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WaypointOptimizationDestinationOptions {
    /// <p>Access hours corresponding to when a waypoint can be visited.</p>
    pub access_hours: ::std::option::Option<crate::types::WaypointOptimizationAccessHours>,
    /// <p>Appointment time at the destination.</p>
    pub appointment_time: ::std::option::Option<::std::string::String>,
    /// <p>GPS Heading at the position.</p>
    pub heading: f64,
    /// <p>The waypoint Id.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>Service time spent at the destination. At an appointment, the service time should be the appointment duration.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub service_duration: i64,
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub side_of_street: ::std::option::Option<crate::types::WaypointOptimizationSideOfStreetOptions>,
}
impl WaypointOptimizationDestinationOptions {
    /// <p>Access hours corresponding to when a waypoint can be visited.</p>
    pub fn access_hours(&self) -> ::std::option::Option<&crate::types::WaypointOptimizationAccessHours> {
        self.access_hours.as_ref()
    }
    /// <p>Appointment time at the destination.</p>
    pub fn appointment_time(&self) -> ::std::option::Option<&str> {
        self.appointment_time.as_deref()
    }
    /// <p>GPS Heading at the position.</p>
    pub fn heading(&self) -> f64 {
        self.heading
    }
    /// <p>The waypoint Id.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>Service time spent at the destination. At an appointment, the service time should be the appointment duration.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn service_duration(&self) -> i64 {
        self.service_duration
    }
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub fn side_of_street(&self) -> ::std::option::Option<&crate::types::WaypointOptimizationSideOfStreetOptions> {
        self.side_of_street.as_ref()
    }
}
impl WaypointOptimizationDestinationOptions {
    /// Creates a new builder-style object to manufacture [`WaypointOptimizationDestinationOptions`](crate::types::WaypointOptimizationDestinationOptions).
    pub fn builder() -> crate::types::builders::WaypointOptimizationDestinationOptionsBuilder {
        crate::types::builders::WaypointOptimizationDestinationOptionsBuilder::default()
    }
}

/// A builder for [`WaypointOptimizationDestinationOptions`](crate::types::WaypointOptimizationDestinationOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WaypointOptimizationDestinationOptionsBuilder {
    pub(crate) access_hours: ::std::option::Option<crate::types::WaypointOptimizationAccessHours>,
    pub(crate) appointment_time: ::std::option::Option<::std::string::String>,
    pub(crate) heading: ::std::option::Option<f64>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) service_duration: ::std::option::Option<i64>,
    pub(crate) side_of_street: ::std::option::Option<crate::types::WaypointOptimizationSideOfStreetOptions>,
}
impl WaypointOptimizationDestinationOptionsBuilder {
    /// <p>Access hours corresponding to when a waypoint can be visited.</p>
    pub fn access_hours(mut self, input: crate::types::WaypointOptimizationAccessHours) -> Self {
        self.access_hours = ::std::option::Option::Some(input);
        self
    }
    /// <p>Access hours corresponding to when a waypoint can be visited.</p>
    pub fn set_access_hours(mut self, input: ::std::option::Option<crate::types::WaypointOptimizationAccessHours>) -> Self {
        self.access_hours = input;
        self
    }
    /// <p>Access hours corresponding to when a waypoint can be visited.</p>
    pub fn get_access_hours(&self) -> &::std::option::Option<crate::types::WaypointOptimizationAccessHours> {
        &self.access_hours
    }
    /// <p>Appointment time at the destination.</p>
    pub fn appointment_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.appointment_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Appointment time at the destination.</p>
    pub fn set_appointment_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.appointment_time = input;
        self
    }
    /// <p>Appointment time at the destination.</p>
    pub fn get_appointment_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.appointment_time
    }
    /// <p>GPS Heading at the position.</p>
    pub fn heading(mut self, input: f64) -> Self {
        self.heading = ::std::option::Option::Some(input);
        self
    }
    /// <p>GPS Heading at the position.</p>
    pub fn set_heading(mut self, input: ::std::option::Option<f64>) -> Self {
        self.heading = input;
        self
    }
    /// <p>GPS Heading at the position.</p>
    pub fn get_heading(&self) -> &::std::option::Option<f64> {
        &self.heading
    }
    /// <p>The waypoint Id.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The waypoint Id.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The waypoint Id.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Service time spent at the destination. At an appointment, the service time should be the appointment duration.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn service_duration(mut self, input: i64) -> Self {
        self.service_duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Service time spent at the destination. At an appointment, the service time should be the appointment duration.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn set_service_duration(mut self, input: ::std::option::Option<i64>) -> Self {
        self.service_duration = input;
        self
    }
    /// <p>Service time spent at the destination. At an appointment, the service time should be the appointment duration.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn get_service_duration(&self) -> &::std::option::Option<i64> {
        &self.service_duration
    }
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub fn side_of_street(mut self, input: crate::types::WaypointOptimizationSideOfStreetOptions) -> Self {
        self.side_of_street = ::std::option::Option::Some(input);
        self
    }
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub fn set_side_of_street(mut self, input: ::std::option::Option<crate::types::WaypointOptimizationSideOfStreetOptions>) -> Self {
        self.side_of_street = input;
        self
    }
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub fn get_side_of_street(&self) -> &::std::option::Option<crate::types::WaypointOptimizationSideOfStreetOptions> {
        &self.side_of_street
    }
    /// Consumes the builder and constructs a [`WaypointOptimizationDestinationOptions`](crate::types::WaypointOptimizationDestinationOptions).
    pub fn build(self) -> crate::types::WaypointOptimizationDestinationOptions {
        crate::types::WaypointOptimizationDestinationOptions {
            access_hours: self.access_hours,
            appointment_time: self.appointment_time,
            heading: self.heading.unwrap_or_default(),
            id: self.id,
            service_duration: self.service_duration.unwrap_or_default(),
            side_of_street: self.side_of_street,
        }
    }
}
