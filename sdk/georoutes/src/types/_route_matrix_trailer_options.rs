// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Trailer options corresponding to the vehicle.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RouteMatrixTrailerOptions {
    /// <p>Number of trailers attached to the vehicle.</p>
    /// <p>Default Value: <code>0</code></p>
    pub trailer_count: ::std::option::Option<i32>,
}
impl RouteMatrixTrailerOptions {
    /// <p>Number of trailers attached to the vehicle.</p>
    /// <p>Default Value: <code>0</code></p>
    pub fn trailer_count(&self) -> ::std::option::Option<i32> {
        self.trailer_count
    }
}
impl RouteMatrixTrailerOptions {
    /// Creates a new builder-style object to manufacture [`RouteMatrixTrailerOptions`](crate::types::RouteMatrixTrailerOptions).
    pub fn builder() -> crate::types::builders::RouteMatrixTrailerOptionsBuilder {
        crate::types::builders::RouteMatrixTrailerOptionsBuilder::default()
    }
}

/// A builder for [`RouteMatrixTrailerOptions`](crate::types::RouteMatrixTrailerOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RouteMatrixTrailerOptionsBuilder {
    pub(crate) trailer_count: ::std::option::Option<i32>,
}
impl RouteMatrixTrailerOptionsBuilder {
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
    /// Consumes the builder and constructs a [`RouteMatrixTrailerOptions`](crate::types::RouteMatrixTrailerOptions).
    pub fn build(self) -> crate::types::RouteMatrixTrailerOptions {
        crate::types::RouteMatrixTrailerOptions {
            trailer_count: self.trailer_count,
        }
    }
}
