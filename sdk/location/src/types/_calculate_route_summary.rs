// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of the calculated route.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CalculateRouteSummary {
    /// <p>Specifies a geographical box surrounding a route. Used to zoom into a route when displaying it in a map. For example, <code>\[min x, min y, max x, max y\]</code>.</p>
    /// <p>The first 2 <code>bbox</code> parameters describe the lower southwest corner:</p>
    /// <ul>
    /// <li>
    /// <p>The first <code>bbox</code> position is the X coordinate or longitude of the lower southwest corner.</p></li>
    /// <li>
    /// <p>The second <code>bbox</code> position is the Y coordinate or latitude of the lower southwest corner.</p></li>
    /// </ul>
    /// <p>The next 2 <code>bbox</code> parameters describe the upper northeast corner:</p>
    /// <ul>
    /// <li>
    /// <p>The third <code>bbox</code> position is the X coordinate, or longitude of the upper northeast corner.</p></li>
    /// <li>
    /// <p>The fourth <code>bbox</code> position is the Y coordinate, or latitude of the upper northeast corner.</p></li>
    /// </ul>
    pub route_b_box: ::std::vec::Vec<f64>,
    /// <p>The data provider of traffic and road network data used to calculate the route. Indicates one of the available providers:</p>
    /// <ul>
    /// <li>
    /// <p><code>Esri</code></p></li>
    /// <li>
    /// <p><code>Grab</code></p></li>
    /// <li>
    /// <p><code>Here</code></p></li>
    /// </ul>
    /// <p>For more information about data providers, see <a href="https://docs.aws.amazon.com/location/latest/developerguide/what-is-data-provider.html">Amazon Location Service data providers</a>.</p>
    pub data_source: ::std::string::String,
    /// <p>The total distance covered by the route. The sum of the distance travelled between every stop on the route.</p><note>
    /// <p>If Esri is the data source for the route calculator, the route distance can’t be greater than 400 km. If the route exceeds 400 km, the response is a <code>400 RoutesValidationException</code> error.</p>
    /// </note>
    pub distance: f64,
    /// <p>The total travel time for the route measured in seconds. The sum of the travel time between every stop on the route.</p>
    pub duration_seconds: f64,
    /// <p>The unit of measurement for route distances.</p>
    pub distance_unit: crate::types::DistanceUnit,
}
impl CalculateRouteSummary {
    /// <p>Specifies a geographical box surrounding a route. Used to zoom into a route when displaying it in a map. For example, <code>\[min x, min y, max x, max y\]</code>.</p>
    /// <p>The first 2 <code>bbox</code> parameters describe the lower southwest corner:</p>
    /// <ul>
    /// <li>
    /// <p>The first <code>bbox</code> position is the X coordinate or longitude of the lower southwest corner.</p></li>
    /// <li>
    /// <p>The second <code>bbox</code> position is the Y coordinate or latitude of the lower southwest corner.</p></li>
    /// </ul>
    /// <p>The next 2 <code>bbox</code> parameters describe the upper northeast corner:</p>
    /// <ul>
    /// <li>
    /// <p>The third <code>bbox</code> position is the X coordinate, or longitude of the upper northeast corner.</p></li>
    /// <li>
    /// <p>The fourth <code>bbox</code> position is the Y coordinate, or latitude of the upper northeast corner.</p></li>
    /// </ul>
    pub fn route_b_box(&self) -> &[f64] {
        use std::ops::Deref;
        self.route_b_box.deref()
    }
    /// <p>The data provider of traffic and road network data used to calculate the route. Indicates one of the available providers:</p>
    /// <ul>
    /// <li>
    /// <p><code>Esri</code></p></li>
    /// <li>
    /// <p><code>Grab</code></p></li>
    /// <li>
    /// <p><code>Here</code></p></li>
    /// </ul>
    /// <p>For more information about data providers, see <a href="https://docs.aws.amazon.com/location/latest/developerguide/what-is-data-provider.html">Amazon Location Service data providers</a>.</p>
    pub fn data_source(&self) -> &str {
        use std::ops::Deref;
        self.data_source.deref()
    }
    /// <p>The total distance covered by the route. The sum of the distance travelled between every stop on the route.</p><note>
    /// <p>If Esri is the data source for the route calculator, the route distance can’t be greater than 400 km. If the route exceeds 400 km, the response is a <code>400 RoutesValidationException</code> error.</p>
    /// </note>
    pub fn distance(&self) -> f64 {
        self.distance
    }
    /// <p>The total travel time for the route measured in seconds. The sum of the travel time between every stop on the route.</p>
    pub fn duration_seconds(&self) -> f64 {
        self.duration_seconds
    }
    /// <p>The unit of measurement for route distances.</p>
    pub fn distance_unit(&self) -> &crate::types::DistanceUnit {
        &self.distance_unit
    }
}
impl ::std::fmt::Debug for CalculateRouteSummary {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CalculateRouteSummary");
        formatter.field("route_b_box", &"*** Sensitive Data Redacted ***");
        formatter.field("data_source", &self.data_source);
        formatter.field("distance", &self.distance);
        formatter.field("duration_seconds", &self.duration_seconds);
        formatter.field("distance_unit", &self.distance_unit);
        formatter.finish()
    }
}
impl CalculateRouteSummary {
    /// Creates a new builder-style object to manufacture [`CalculateRouteSummary`](crate::types::CalculateRouteSummary).
    pub fn builder() -> crate::types::builders::CalculateRouteSummaryBuilder {
        crate::types::builders::CalculateRouteSummaryBuilder::default()
    }
}

/// A builder for [`CalculateRouteSummary`](crate::types::CalculateRouteSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CalculateRouteSummaryBuilder {
    pub(crate) route_b_box: ::std::option::Option<::std::vec::Vec<f64>>,
    pub(crate) data_source: ::std::option::Option<::std::string::String>,
    pub(crate) distance: ::std::option::Option<f64>,
    pub(crate) duration_seconds: ::std::option::Option<f64>,
    pub(crate) distance_unit: ::std::option::Option<crate::types::DistanceUnit>,
}
impl CalculateRouteSummaryBuilder {
    /// Appends an item to `route_b_box`.
    ///
    /// To override the contents of this collection use [`set_route_b_box`](Self::set_route_b_box).
    ///
    /// <p>Specifies a geographical box surrounding a route. Used to zoom into a route when displaying it in a map. For example, <code>\[min x, min y, max x, max y\]</code>.</p>
    /// <p>The first 2 <code>bbox</code> parameters describe the lower southwest corner:</p>
    /// <ul>
    /// <li>
    /// <p>The first <code>bbox</code> position is the X coordinate or longitude of the lower southwest corner.</p></li>
    /// <li>
    /// <p>The second <code>bbox</code> position is the Y coordinate or latitude of the lower southwest corner.</p></li>
    /// </ul>
    /// <p>The next 2 <code>bbox</code> parameters describe the upper northeast corner:</p>
    /// <ul>
    /// <li>
    /// <p>The third <code>bbox</code> position is the X coordinate, or longitude of the upper northeast corner.</p></li>
    /// <li>
    /// <p>The fourth <code>bbox</code> position is the Y coordinate, or latitude of the upper northeast corner.</p></li>
    /// </ul>
    pub fn route_b_box(mut self, input: f64) -> Self {
        let mut v = self.route_b_box.unwrap_or_default();
        v.push(input);
        self.route_b_box = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies a geographical box surrounding a route. Used to zoom into a route when displaying it in a map. For example, <code>\[min x, min y, max x, max y\]</code>.</p>
    /// <p>The first 2 <code>bbox</code> parameters describe the lower southwest corner:</p>
    /// <ul>
    /// <li>
    /// <p>The first <code>bbox</code> position is the X coordinate or longitude of the lower southwest corner.</p></li>
    /// <li>
    /// <p>The second <code>bbox</code> position is the Y coordinate or latitude of the lower southwest corner.</p></li>
    /// </ul>
    /// <p>The next 2 <code>bbox</code> parameters describe the upper northeast corner:</p>
    /// <ul>
    /// <li>
    /// <p>The third <code>bbox</code> position is the X coordinate, or longitude of the upper northeast corner.</p></li>
    /// <li>
    /// <p>The fourth <code>bbox</code> position is the Y coordinate, or latitude of the upper northeast corner.</p></li>
    /// </ul>
    pub fn set_route_b_box(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.route_b_box = input;
        self
    }
    /// <p>Specifies a geographical box surrounding a route. Used to zoom into a route when displaying it in a map. For example, <code>\[min x, min y, max x, max y\]</code>.</p>
    /// <p>The first 2 <code>bbox</code> parameters describe the lower southwest corner:</p>
    /// <ul>
    /// <li>
    /// <p>The first <code>bbox</code> position is the X coordinate or longitude of the lower southwest corner.</p></li>
    /// <li>
    /// <p>The second <code>bbox</code> position is the Y coordinate or latitude of the lower southwest corner.</p></li>
    /// </ul>
    /// <p>The next 2 <code>bbox</code> parameters describe the upper northeast corner:</p>
    /// <ul>
    /// <li>
    /// <p>The third <code>bbox</code> position is the X coordinate, or longitude of the upper northeast corner.</p></li>
    /// <li>
    /// <p>The fourth <code>bbox</code> position is the Y coordinate, or latitude of the upper northeast corner.</p></li>
    /// </ul>
    pub fn get_route_b_box(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.route_b_box
    }
    /// <p>The data provider of traffic and road network data used to calculate the route. Indicates one of the available providers:</p>
    /// <ul>
    /// <li>
    /// <p><code>Esri</code></p></li>
    /// <li>
    /// <p><code>Grab</code></p></li>
    /// <li>
    /// <p><code>Here</code></p></li>
    /// </ul>
    /// <p>For more information about data providers, see <a href="https://docs.aws.amazon.com/location/latest/developerguide/what-is-data-provider.html">Amazon Location Service data providers</a>.</p>
    /// This field is required.
    pub fn data_source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The data provider of traffic and road network data used to calculate the route. Indicates one of the available providers:</p>
    /// <ul>
    /// <li>
    /// <p><code>Esri</code></p></li>
    /// <li>
    /// <p><code>Grab</code></p></li>
    /// <li>
    /// <p><code>Here</code></p></li>
    /// </ul>
    /// <p>For more information about data providers, see <a href="https://docs.aws.amazon.com/location/latest/developerguide/what-is-data-provider.html">Amazon Location Service data providers</a>.</p>
    pub fn set_data_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source = input;
        self
    }
    /// <p>The data provider of traffic and road network data used to calculate the route. Indicates one of the available providers:</p>
    /// <ul>
    /// <li>
    /// <p><code>Esri</code></p></li>
    /// <li>
    /// <p><code>Grab</code></p></li>
    /// <li>
    /// <p><code>Here</code></p></li>
    /// </ul>
    /// <p>For more information about data providers, see <a href="https://docs.aws.amazon.com/location/latest/developerguide/what-is-data-provider.html">Amazon Location Service data providers</a>.</p>
    pub fn get_data_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source
    }
    /// <p>The total distance covered by the route. The sum of the distance travelled between every stop on the route.</p><note>
    /// <p>If Esri is the data source for the route calculator, the route distance can’t be greater than 400 km. If the route exceeds 400 km, the response is a <code>400 RoutesValidationException</code> error.</p>
    /// </note>
    /// This field is required.
    pub fn distance(mut self, input: f64) -> Self {
        self.distance = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total distance covered by the route. The sum of the distance travelled between every stop on the route.</p><note>
    /// <p>If Esri is the data source for the route calculator, the route distance can’t be greater than 400 km. If the route exceeds 400 km, the response is a <code>400 RoutesValidationException</code> error.</p>
    /// </note>
    pub fn set_distance(mut self, input: ::std::option::Option<f64>) -> Self {
        self.distance = input;
        self
    }
    /// <p>The total distance covered by the route. The sum of the distance travelled between every stop on the route.</p><note>
    /// <p>If Esri is the data source for the route calculator, the route distance can’t be greater than 400 km. If the route exceeds 400 km, the response is a <code>400 RoutesValidationException</code> error.</p>
    /// </note>
    pub fn get_distance(&self) -> &::std::option::Option<f64> {
        &self.distance
    }
    /// <p>The total travel time for the route measured in seconds. The sum of the travel time between every stop on the route.</p>
    /// This field is required.
    pub fn duration_seconds(mut self, input: f64) -> Self {
        self.duration_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total travel time for the route measured in seconds. The sum of the travel time between every stop on the route.</p>
    pub fn set_duration_seconds(mut self, input: ::std::option::Option<f64>) -> Self {
        self.duration_seconds = input;
        self
    }
    /// <p>The total travel time for the route measured in seconds. The sum of the travel time between every stop on the route.</p>
    pub fn get_duration_seconds(&self) -> &::std::option::Option<f64> {
        &self.duration_seconds
    }
    /// <p>The unit of measurement for route distances.</p>
    /// This field is required.
    pub fn distance_unit(mut self, input: crate::types::DistanceUnit) -> Self {
        self.distance_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unit of measurement for route distances.</p>
    pub fn set_distance_unit(mut self, input: ::std::option::Option<crate::types::DistanceUnit>) -> Self {
        self.distance_unit = input;
        self
    }
    /// <p>The unit of measurement for route distances.</p>
    pub fn get_distance_unit(&self) -> &::std::option::Option<crate::types::DistanceUnit> {
        &self.distance_unit
    }
    /// Consumes the builder and constructs a [`CalculateRouteSummary`](crate::types::CalculateRouteSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`route_b_box`](crate::types::builders::CalculateRouteSummaryBuilder::route_b_box)
    /// - [`data_source`](crate::types::builders::CalculateRouteSummaryBuilder::data_source)
    /// - [`distance`](crate::types::builders::CalculateRouteSummaryBuilder::distance)
    /// - [`duration_seconds`](crate::types::builders::CalculateRouteSummaryBuilder::duration_seconds)
    /// - [`distance_unit`](crate::types::builders::CalculateRouteSummaryBuilder::distance_unit)
    pub fn build(self) -> ::std::result::Result<crate::types::CalculateRouteSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CalculateRouteSummary {
            route_b_box: self.route_b_box.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "route_b_box",
                    "route_b_box was not specified but it is required when building CalculateRouteSummary",
                )
            })?,
            data_source: self.data_source.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_source",
                    "data_source was not specified but it is required when building CalculateRouteSummary",
                )
            })?,
            distance: self.distance.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "distance",
                    "distance was not specified but it is required when building CalculateRouteSummary",
                )
            })?,
            duration_seconds: self.duration_seconds.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "duration_seconds",
                    "duration_seconds was not specified but it is required when building CalculateRouteSummary",
                )
            })?,
            distance_unit: self.distance_unit.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "distance_unit",
                    "distance_unit was not specified but it is required when building CalculateRouteSummary",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for CalculateRouteSummaryBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CalculateRouteSummaryBuilder");
        formatter.field("route_b_box", &"*** Sensitive Data Redacted ***");
        formatter.field("data_source", &self.data_source);
        formatter.field("distance", &self.distance);
        formatter.field("duration_seconds", &self.duration_seconds);
        formatter.field("distance_unit", &self.distance_unit);
        formatter.finish()
    }
}
