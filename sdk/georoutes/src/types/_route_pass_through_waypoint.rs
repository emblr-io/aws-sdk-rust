// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>If the waypoint should be treated as a stop. If yes, the route is split up into different legs around the stop.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RoutePassThroughWaypoint {
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub geometry_offset: ::std::option::Option<i32>,
    /// <p>The place details.</p>
    pub place: ::std::option::Option<crate::types::RoutePassThroughPlace>,
}
impl RoutePassThroughWaypoint {
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub fn geometry_offset(&self) -> ::std::option::Option<i32> {
        self.geometry_offset
    }
    /// <p>The place details.</p>
    pub fn place(&self) -> ::std::option::Option<&crate::types::RoutePassThroughPlace> {
        self.place.as_ref()
    }
}
impl RoutePassThroughWaypoint {
    /// Creates a new builder-style object to manufacture [`RoutePassThroughWaypoint`](crate::types::RoutePassThroughWaypoint).
    pub fn builder() -> crate::types::builders::RoutePassThroughWaypointBuilder {
        crate::types::builders::RoutePassThroughWaypointBuilder::default()
    }
}

/// A builder for [`RoutePassThroughWaypoint`](crate::types::RoutePassThroughWaypoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RoutePassThroughWaypointBuilder {
    pub(crate) geometry_offset: ::std::option::Option<i32>,
    pub(crate) place: ::std::option::Option<crate::types::RoutePassThroughPlace>,
}
impl RoutePassThroughWaypointBuilder {
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub fn geometry_offset(mut self, input: i32) -> Self {
        self.geometry_offset = ::std::option::Option::Some(input);
        self
    }
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub fn set_geometry_offset(mut self, input: ::std::option::Option<i32>) -> Self {
        self.geometry_offset = input;
        self
    }
    /// <p>Offset in the leg geometry corresponding to the start of this step.</p>
    pub fn get_geometry_offset(&self) -> &::std::option::Option<i32> {
        &self.geometry_offset
    }
    /// <p>The place details.</p>
    /// This field is required.
    pub fn place(mut self, input: crate::types::RoutePassThroughPlace) -> Self {
        self.place = ::std::option::Option::Some(input);
        self
    }
    /// <p>The place details.</p>
    pub fn set_place(mut self, input: ::std::option::Option<crate::types::RoutePassThroughPlace>) -> Self {
        self.place = input;
        self
    }
    /// <p>The place details.</p>
    pub fn get_place(&self) -> &::std::option::Option<crate::types::RoutePassThroughPlace> {
        &self.place
    }
    /// Consumes the builder and constructs a [`RoutePassThroughWaypoint`](crate::types::RoutePassThroughWaypoint).
    pub fn build(self) -> crate::types::RoutePassThroughWaypoint {
        crate::types::RoutePassThroughWaypoint {
            geometry_offset: self.geometry_offset,
            place: self.place,
        }
    }
}
