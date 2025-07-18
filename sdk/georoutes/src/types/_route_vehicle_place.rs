// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Place details corresponding to the arrival or departure.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct RouteVehiclePlace {
    /// <p>The name of the place.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Position provided in the request.</p>
    pub original_position: ::std::option::Option<::std::vec::Vec<f64>>,
    /// <p>Position defined as <code>\[longitude, latitude\]</code>.</p>
    pub position: ::std::vec::Vec<f64>,
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub side_of_street: ::std::option::Option<crate::types::RouteSideOfStreet>,
    /// <p>Index of the waypoint in the request.</p>
    pub waypoint_index: ::std::option::Option<i32>,
}
impl RouteVehiclePlace {
    /// <p>The name of the place.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Position provided in the request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.original_position.is_none()`.
    pub fn original_position(&self) -> &[f64] {
        self.original_position.as_deref().unwrap_or_default()
    }
    /// <p>Position defined as <code>\[longitude, latitude\]</code>.</p>
    pub fn position(&self) -> &[f64] {
        use std::ops::Deref;
        self.position.deref()
    }
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub fn side_of_street(&self) -> ::std::option::Option<&crate::types::RouteSideOfStreet> {
        self.side_of_street.as_ref()
    }
    /// <p>Index of the waypoint in the request.</p>
    pub fn waypoint_index(&self) -> ::std::option::Option<i32> {
        self.waypoint_index
    }
}
impl ::std::fmt::Debug for RouteVehiclePlace {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RouteVehiclePlace");
        formatter.field("name", &self.name);
        formatter.field("original_position", &"*** Sensitive Data Redacted ***");
        formatter.field("position", &"*** Sensitive Data Redacted ***");
        formatter.field("side_of_street", &self.side_of_street);
        formatter.field("waypoint_index", &self.waypoint_index);
        formatter.finish()
    }
}
impl RouteVehiclePlace {
    /// Creates a new builder-style object to manufacture [`RouteVehiclePlace`](crate::types::RouteVehiclePlace).
    pub fn builder() -> crate::types::builders::RouteVehiclePlaceBuilder {
        crate::types::builders::RouteVehiclePlaceBuilder::default()
    }
}

/// A builder for [`RouteVehiclePlace`](crate::types::RouteVehiclePlace).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct RouteVehiclePlaceBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) original_position: ::std::option::Option<::std::vec::Vec<f64>>,
    pub(crate) position: ::std::option::Option<::std::vec::Vec<f64>>,
    pub(crate) side_of_street: ::std::option::Option<crate::types::RouteSideOfStreet>,
    pub(crate) waypoint_index: ::std::option::Option<i32>,
}
impl RouteVehiclePlaceBuilder {
    /// <p>The name of the place.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the place.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the place.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `original_position`.
    ///
    /// To override the contents of this collection use [`set_original_position`](Self::set_original_position).
    ///
    /// <p>Position provided in the request.</p>
    pub fn original_position(mut self, input: f64) -> Self {
        let mut v = self.original_position.unwrap_or_default();
        v.push(input);
        self.original_position = ::std::option::Option::Some(v);
        self
    }
    /// <p>Position provided in the request.</p>
    pub fn set_original_position(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.original_position = input;
        self
    }
    /// <p>Position provided in the request.</p>
    pub fn get_original_position(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.original_position
    }
    /// Appends an item to `position`.
    ///
    /// To override the contents of this collection use [`set_position`](Self::set_position).
    ///
    /// <p>Position defined as <code>\[longitude, latitude\]</code>.</p>
    pub fn position(mut self, input: f64) -> Self {
        let mut v = self.position.unwrap_or_default();
        v.push(input);
        self.position = ::std::option::Option::Some(v);
        self
    }
    /// <p>Position defined as <code>\[longitude, latitude\]</code>.</p>
    pub fn set_position(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.position = input;
        self
    }
    /// <p>Position defined as <code>\[longitude, latitude\]</code>.</p>
    pub fn get_position(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.position
    }
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub fn side_of_street(mut self, input: crate::types::RouteSideOfStreet) -> Self {
        self.side_of_street = ::std::option::Option::Some(input);
        self
    }
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub fn set_side_of_street(mut self, input: ::std::option::Option<crate::types::RouteSideOfStreet>) -> Self {
        self.side_of_street = input;
        self
    }
    /// <p>Options to configure matching the provided position to a side of the street.</p>
    pub fn get_side_of_street(&self) -> &::std::option::Option<crate::types::RouteSideOfStreet> {
        &self.side_of_street
    }
    /// <p>Index of the waypoint in the request.</p>
    pub fn waypoint_index(mut self, input: i32) -> Self {
        self.waypoint_index = ::std::option::Option::Some(input);
        self
    }
    /// <p>Index of the waypoint in the request.</p>
    pub fn set_waypoint_index(mut self, input: ::std::option::Option<i32>) -> Self {
        self.waypoint_index = input;
        self
    }
    /// <p>Index of the waypoint in the request.</p>
    pub fn get_waypoint_index(&self) -> &::std::option::Option<i32> {
        &self.waypoint_index
    }
    /// Consumes the builder and constructs a [`RouteVehiclePlace`](crate::types::RouteVehiclePlace).
    /// This method will fail if any of the following fields are not set:
    /// - [`position`](crate::types::builders::RouteVehiclePlaceBuilder::position)
    pub fn build(self) -> ::std::result::Result<crate::types::RouteVehiclePlace, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RouteVehiclePlace {
            name: self.name,
            original_position: self.original_position,
            position: self.position.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "position",
                    "position was not specified but it is required when building RouteVehiclePlace",
                )
            })?,
            side_of_street: self.side_of_street,
            waypoint_index: self.waypoint_index,
        })
    }
}
impl ::std::fmt::Debug for RouteVehiclePlaceBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RouteVehiclePlaceBuilder");
        formatter.field("name", &self.name);
        formatter.field("original_position", &"*** Sensitive Data Redacted ***");
        formatter.field("position", &"*** Sensitive Data Redacted ***");
        formatter.field("side_of_street", &self.side_of_street);
        formatter.field("waypoint_index", &self.waypoint_index);
        formatter.finish()
    }
}
