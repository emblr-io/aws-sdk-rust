// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details corresponding to the arrival for a leg.</p>
/// <p>Time format:<code>YYYY-MM-DDThh:mm:ss.sssZ | YYYY-MM-DDThh:mm:ss.sss+hh:mm</code></p>
/// <p>Examples:</p>
/// <p><code>2020-04-22T17:57:24Z</code></p>
/// <p><code>2020-04-22T17:57:24+02:00</code></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RoutePedestrianArrival {
    /// <p>The place details.</p>
    pub place: ::std::option::Option<crate::types::RoutePedestrianPlace>,
    /// <p>The time.</p>
    pub time: ::std::option::Option<::std::string::String>,
}
impl RoutePedestrianArrival {
    /// <p>The place details.</p>
    pub fn place(&self) -> ::std::option::Option<&crate::types::RoutePedestrianPlace> {
        self.place.as_ref()
    }
    /// <p>The time.</p>
    pub fn time(&self) -> ::std::option::Option<&str> {
        self.time.as_deref()
    }
}
impl RoutePedestrianArrival {
    /// Creates a new builder-style object to manufacture [`RoutePedestrianArrival`](crate::types::RoutePedestrianArrival).
    pub fn builder() -> crate::types::builders::RoutePedestrianArrivalBuilder {
        crate::types::builders::RoutePedestrianArrivalBuilder::default()
    }
}

/// A builder for [`RoutePedestrianArrival`](crate::types::RoutePedestrianArrival).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RoutePedestrianArrivalBuilder {
    pub(crate) place: ::std::option::Option<crate::types::RoutePedestrianPlace>,
    pub(crate) time: ::std::option::Option<::std::string::String>,
}
impl RoutePedestrianArrivalBuilder {
    /// <p>The place details.</p>
    /// This field is required.
    pub fn place(mut self, input: crate::types::RoutePedestrianPlace) -> Self {
        self.place = ::std::option::Option::Some(input);
        self
    }
    /// <p>The place details.</p>
    pub fn set_place(mut self, input: ::std::option::Option<crate::types::RoutePedestrianPlace>) -> Self {
        self.place = input;
        self
    }
    /// <p>The place details.</p>
    pub fn get_place(&self) -> &::std::option::Option<crate::types::RoutePedestrianPlace> {
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
    /// Consumes the builder and constructs a [`RoutePedestrianArrival`](crate::types::RoutePedestrianArrival).
    pub fn build(self) -> crate::types::RoutePedestrianArrival {
        crate::types::RoutePedestrianArrival {
            place: self.place,
            time: self.time,
        }
    }
}
