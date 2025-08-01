// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for DescribeMultiplexResponse
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeMultiplexOutput {
    /// The unique arn of the multiplex.
    pub arn: ::std::option::Option<::std::string::String>,
    /// A list of availability zones for the multiplex.
    pub availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// A list of the multiplex output destinations.
    pub destinations: ::std::option::Option<::std::vec::Vec<crate::types::MultiplexOutputDestination>>,
    /// The unique id of the multiplex.
    pub id: ::std::option::Option<::std::string::String>,
    /// Configuration for a multiplex event.
    pub multiplex_settings: ::std::option::Option<crate::types::MultiplexSettings>,
    /// The name of the multiplex.
    pub name: ::std::option::Option<::std::string::String>,
    /// The number of currently healthy pipelines.
    pub pipelines_running_count: ::std::option::Option<i32>,
    /// The number of programs in the multiplex.
    pub program_count: ::std::option::Option<i32>,
    /// The current state of the multiplex.
    pub state: ::std::option::Option<crate::types::MultiplexState>,
    /// A collection of key-value pairs.
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl DescribeMultiplexOutput {
    /// The unique arn of the multiplex.
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// A list of availability zones for the multiplex.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.availability_zones.is_none()`.
    pub fn availability_zones(&self) -> &[::std::string::String] {
        self.availability_zones.as_deref().unwrap_or_default()
    }
    /// A list of the multiplex output destinations.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.destinations.is_none()`.
    pub fn destinations(&self) -> &[crate::types::MultiplexOutputDestination] {
        self.destinations.as_deref().unwrap_or_default()
    }
    /// The unique id of the multiplex.
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// Configuration for a multiplex event.
    pub fn multiplex_settings(&self) -> ::std::option::Option<&crate::types::MultiplexSettings> {
        self.multiplex_settings.as_ref()
    }
    /// The name of the multiplex.
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// The number of currently healthy pipelines.
    pub fn pipelines_running_count(&self) -> ::std::option::Option<i32> {
        self.pipelines_running_count
    }
    /// The number of programs in the multiplex.
    pub fn program_count(&self) -> ::std::option::Option<i32> {
        self.program_count
    }
    /// The current state of the multiplex.
    pub fn state(&self) -> ::std::option::Option<&crate::types::MultiplexState> {
        self.state.as_ref()
    }
    /// A collection of key-value pairs.
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeMultiplexOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeMultiplexOutput {
    /// Creates a new builder-style object to manufacture [`DescribeMultiplexOutput`](crate::operation::describe_multiplex::DescribeMultiplexOutput).
    pub fn builder() -> crate::operation::describe_multiplex::builders::DescribeMultiplexOutputBuilder {
        crate::operation::describe_multiplex::builders::DescribeMultiplexOutputBuilder::default()
    }
}

/// A builder for [`DescribeMultiplexOutput`](crate::operation::describe_multiplex::DescribeMultiplexOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeMultiplexOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) destinations: ::std::option::Option<::std::vec::Vec<crate::types::MultiplexOutputDestination>>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) multiplex_settings: ::std::option::Option<crate::types::MultiplexSettings>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) pipelines_running_count: ::std::option::Option<i32>,
    pub(crate) program_count: ::std::option::Option<i32>,
    pub(crate) state: ::std::option::Option<crate::types::MultiplexState>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl DescribeMultiplexOutputBuilder {
    /// The unique arn of the multiplex.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The unique arn of the multiplex.
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// The unique arn of the multiplex.
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Appends an item to `availability_zones`.
    ///
    /// To override the contents of this collection use [`set_availability_zones`](Self::set_availability_zones).
    ///
    /// A list of availability zones for the multiplex.
    pub fn availability_zones(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.availability_zones.unwrap_or_default();
        v.push(input.into());
        self.availability_zones = ::std::option::Option::Some(v);
        self
    }
    /// A list of availability zones for the multiplex.
    pub fn set_availability_zones(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.availability_zones = input;
        self
    }
    /// A list of availability zones for the multiplex.
    pub fn get_availability_zones(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.availability_zones
    }
    /// Appends an item to `destinations`.
    ///
    /// To override the contents of this collection use [`set_destinations`](Self::set_destinations).
    ///
    /// A list of the multiplex output destinations.
    pub fn destinations(mut self, input: crate::types::MultiplexOutputDestination) -> Self {
        let mut v = self.destinations.unwrap_or_default();
        v.push(input);
        self.destinations = ::std::option::Option::Some(v);
        self
    }
    /// A list of the multiplex output destinations.
    pub fn set_destinations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MultiplexOutputDestination>>) -> Self {
        self.destinations = input;
        self
    }
    /// A list of the multiplex output destinations.
    pub fn get_destinations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MultiplexOutputDestination>> {
        &self.destinations
    }
    /// The unique id of the multiplex.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// The unique id of the multiplex.
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// The unique id of the multiplex.
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Configuration for a multiplex event.
    pub fn multiplex_settings(mut self, input: crate::types::MultiplexSettings) -> Self {
        self.multiplex_settings = ::std::option::Option::Some(input);
        self
    }
    /// Configuration for a multiplex event.
    pub fn set_multiplex_settings(mut self, input: ::std::option::Option<crate::types::MultiplexSettings>) -> Self {
        self.multiplex_settings = input;
        self
    }
    /// Configuration for a multiplex event.
    pub fn get_multiplex_settings(&self) -> &::std::option::Option<crate::types::MultiplexSettings> {
        &self.multiplex_settings
    }
    /// The name of the multiplex.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// The name of the multiplex.
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// The name of the multiplex.
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// The number of currently healthy pipelines.
    pub fn pipelines_running_count(mut self, input: i32) -> Self {
        self.pipelines_running_count = ::std::option::Option::Some(input);
        self
    }
    /// The number of currently healthy pipelines.
    pub fn set_pipelines_running_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.pipelines_running_count = input;
        self
    }
    /// The number of currently healthy pipelines.
    pub fn get_pipelines_running_count(&self) -> &::std::option::Option<i32> {
        &self.pipelines_running_count
    }
    /// The number of programs in the multiplex.
    pub fn program_count(mut self, input: i32) -> Self {
        self.program_count = ::std::option::Option::Some(input);
        self
    }
    /// The number of programs in the multiplex.
    pub fn set_program_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.program_count = input;
        self
    }
    /// The number of programs in the multiplex.
    pub fn get_program_count(&self) -> &::std::option::Option<i32> {
        &self.program_count
    }
    /// The current state of the multiplex.
    pub fn state(mut self, input: crate::types::MultiplexState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// The current state of the multiplex.
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::MultiplexState>) -> Self {
        self.state = input;
        self
    }
    /// The current state of the multiplex.
    pub fn get_state(&self) -> &::std::option::Option<crate::types::MultiplexState> {
        &self.state
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// A collection of key-value pairs.
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// A collection of key-value pairs.
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// A collection of key-value pairs.
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeMultiplexOutput`](crate::operation::describe_multiplex::DescribeMultiplexOutput).
    pub fn build(self) -> crate::operation::describe_multiplex::DescribeMultiplexOutput {
        crate::operation::describe_multiplex::DescribeMultiplexOutput {
            arn: self.arn,
            availability_zones: self.availability_zones,
            destinations: self.destinations,
            id: self.id,
            multiplex_settings: self.multiplex_settings,
            name: self.name,
            pipelines_running_count: self.pipelines_running_count,
            program_count: self.program_count,
            state: self.state,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
