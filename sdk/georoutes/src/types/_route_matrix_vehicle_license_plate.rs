// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The vehicle License Plate.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RouteMatrixVehicleLicensePlate {
    /// <p>The last character of the License Plate.</p>
    pub last_character: ::std::option::Option<::std::string::String>,
}
impl RouteMatrixVehicleLicensePlate {
    /// <p>The last character of the License Plate.</p>
    pub fn last_character(&self) -> ::std::option::Option<&str> {
        self.last_character.as_deref()
    }
}
impl RouteMatrixVehicleLicensePlate {
    /// Creates a new builder-style object to manufacture [`RouteMatrixVehicleLicensePlate`](crate::types::RouteMatrixVehicleLicensePlate).
    pub fn builder() -> crate::types::builders::RouteMatrixVehicleLicensePlateBuilder {
        crate::types::builders::RouteMatrixVehicleLicensePlateBuilder::default()
    }
}

/// A builder for [`RouteMatrixVehicleLicensePlate`](crate::types::RouteMatrixVehicleLicensePlate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RouteMatrixVehicleLicensePlateBuilder {
    pub(crate) last_character: ::std::option::Option<::std::string::String>,
}
impl RouteMatrixVehicleLicensePlateBuilder {
    /// <p>The last character of the License Plate.</p>
    pub fn last_character(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_character = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The last character of the License Plate.</p>
    pub fn set_last_character(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_character = input;
        self
    }
    /// <p>The last character of the License Plate.</p>
    pub fn get_last_character(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_character
    }
    /// Consumes the builder and constructs a [`RouteMatrixVehicleLicensePlate`](crate::types::RouteMatrixVehicleLicensePlate).
    pub fn build(self) -> crate::types::RouteMatrixVehicleLicensePlate {
        crate::types::RouteMatrixVehicleLicensePlate {
            last_character: self.last_character,
        }
    }
}
