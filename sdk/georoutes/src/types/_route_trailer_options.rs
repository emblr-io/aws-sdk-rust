// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Trailer options corresponding to the vehicle.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RouteTrailerOptions {
    /// <p>Total number of axles of the vehicle.</p>
    pub axle_count: ::std::option::Option<i32>,
    /// <p>Number of trailers attached to the vehicle.</p>
    /// <p>Default Value: <code>0</code></p>
    pub trailer_count: ::std::option::Option<i32>,
}
impl RouteTrailerOptions {
    /// <p>Total number of axles of the vehicle.</p>
    pub fn axle_count(&self) -> ::std::option::Option<i32> {
        self.axle_count
    }
    /// <p>Number of trailers attached to the vehicle.</p>
    /// <p>Default Value: <code>0</code></p>
    pub fn trailer_count(&self) -> ::std::option::Option<i32> {
        self.trailer_count
    }
}
impl RouteTrailerOptions {
    /// Creates a new builder-style object to manufacture [`RouteTrailerOptions`](crate::types::RouteTrailerOptions).
    pub fn builder() -> crate::types::builders::RouteTrailerOptionsBuilder {
        crate::types::builders::RouteTrailerOptionsBuilder::default()
    }
}

/// A builder for [`RouteTrailerOptions`](crate::types::RouteTrailerOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RouteTrailerOptionsBuilder {
    pub(crate) axle_count: ::std::option::Option<i32>,
    pub(crate) trailer_count: ::std::option::Option<i32>,
}
impl RouteTrailerOptionsBuilder {
    /// <p>Total number of axles of the vehicle.</p>
    pub fn axle_count(mut self, input: i32) -> Self {
        self.axle_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Total number of axles of the vehicle.</p>
    pub fn set_axle_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.axle_count = input;
        self
    }
    /// <p>Total number of axles of the vehicle.</p>
    pub fn get_axle_count(&self) -> &::std::option::Option<i32> {
        &self.axle_count
    }
    /// <p>Number of trailers attached to the vehicle.</p>
    /// <p>Default Value: <code>0</code></p>
    pub fn trailer_count(mut self, input: i32) -> Self {
        self.trailer_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Number of trailers attached to the vehicle.</p>
    /// <p>Default Value: <code>0</code></p>
    pub fn set_trailer_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.trailer_count = input;
        self
    }
    /// <p>Number of trailers attached to the vehicle.</p>
    /// <p>Default Value: <code>0</code></p>
    pub fn get_trailer_count(&self) -> &::std::option::Option<i32> {
        &self.trailer_count
    }
    /// Consumes the builder and constructs a [`RouteTrailerOptions`](crate::types::RouteTrailerOptions).
    pub fn build(self) -> crate::types::RouteTrailerOptions {
        crate::types::RouteTrailerOptions {
            axle_count: self.axle_count,
            trailer_count: self.trailer_count,
        }
    }
}
