// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details corresponding to the arrival for a leg.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RouteVehicleArrival {
    /// <p>The place details.</p>
    pub place: ::std::option::Option<crate::types::RouteVehiclePlace>,
    /// <p>The time.</p>
    pub time: ::std::option::Option<::std::string::String>,
}
impl RouteVehicleArrival {
    /// <p>The place details.</p>
    pub fn place(&self) -> ::std::option::Option<&crate::types::RouteVehiclePlace> {
        self.place.as_ref()
    }
    /// <p>The time.</p>
    pub fn time(&self) -> ::std::option::Option<&str> {
        self.time.as_deref()
    }
}
impl RouteVehicleArrival {
    /// Creates a new builder-style object to manufacture [`RouteVehicleArrival`](crate::types::RouteVehicleArrival).
    pub fn builder() -> crate::types::builders::RouteVehicleArrivalBuilder {
        crate::types::builders::RouteVehicleArrivalBuilder::default()
    }
}

/// A builder for [`RouteVehicleArrival`](crate::types::RouteVehicleArrival).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RouteVehicleArrivalBuilder {
    pub(crate) place: ::std::option::Option<crate::types::RouteVehiclePlace>,
    pub(crate) time: ::std::option::Option<::std::string::String>,
}
impl RouteVehicleArrivalBuilder {
    /// <p>The place details.</p>
    /// This field is required.
    pub fn place(mut self, input: crate::types::RouteVehiclePlace) -> Self {
        self.place = ::std::option::Option::Some(input);
        self
    }
    /// <p>The place details.</p>
    pub fn set_place(mut self, input: ::std::option::Option<crate::types::RouteVehiclePlace>) -> Self {
        self.place = input;
        self
    }
    /// <p>The place details.</p>
    pub fn get_place(&self) -> &::std::option::Option<crate::types::RouteVehiclePlace> {
        &self.place
    }
    /// <p>The time.</p>
    pub fn time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time.</p>
    pub fn set_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.time = input;
        self
    }
    /// <p>The time.</p>
    pub fn get_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.time
    }
    /// Consumes the builder and constructs a [`RouteVehicleArrival`](crate::types::RouteVehicleArrival).
    pub fn build(self) -> crate::types::RouteVehicleArrival {
        crate::types::RouteVehicleArrival {
            place: self.place,
            time: self.time,
        }
    }
}
