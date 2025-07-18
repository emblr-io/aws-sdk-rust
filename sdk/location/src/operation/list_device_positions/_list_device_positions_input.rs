// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDevicePositionsInput {
    /// <p>The tracker resource containing the requested devices.</p>
    pub tracker_name: ::std::option::Option<::std::string::String>,
    /// <p>An optional limit for the number of entries returned in a single call.</p>
    /// <p>Default value: <code>100</code></p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    /// <p>Default value: <code>null</code></p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The geometry used to filter device positions.</p>
    pub filter_geometry: ::std::option::Option<crate::types::TrackingFilterGeometry>,
}
impl ListDevicePositionsInput {
    /// <p>The tracker resource containing the requested devices.</p>
    pub fn tracker_name(&self) -> ::std::option::Option<&str> {
        self.tracker_name.as_deref()
    }
    /// <p>An optional limit for the number of entries returned in a single call.</p>
    /// <p>Default value: <code>100</code></p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    /// <p>Default value: <code>null</code></p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The geometry used to filter device positions.</p>
    pub fn filter_geometry(&self) -> ::std::option::Option<&crate::types::TrackingFilterGeometry> {
        self.filter_geometry.as_ref()
    }
}
impl ListDevicePositionsInput {
    /// Creates a new builder-style object to manufacture [`ListDevicePositionsInput`](crate::operation::list_device_positions::ListDevicePositionsInput).
    pub fn builder() -> crate::operation::list_device_positions::builders::ListDevicePositionsInputBuilder {
        crate::operation::list_device_positions::builders::ListDevicePositionsInputBuilder::default()
    }
}

/// A builder for [`ListDevicePositionsInput`](crate::operation::list_device_positions::ListDevicePositionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDevicePositionsInputBuilder {
    pub(crate) tracker_name: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) filter_geometry: ::std::option::Option<crate::types::TrackingFilterGeometry>,
}
impl ListDevicePositionsInputBuilder {
    /// <p>The tracker resource containing the requested devices.</p>
    /// This field is required.
    pub fn tracker_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tracker_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The tracker resource containing the requested devices.</p>
    pub fn set_tracker_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tracker_name = input;
        self
    }
    /// <p>The tracker resource containing the requested devices.</p>
    pub fn get_tracker_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.tracker_name
    }
    /// <p>An optional limit for the number of entries returned in a single call.</p>
    /// <p>Default value: <code>100</code></p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>An optional limit for the number of entries returned in a single call.</p>
    /// <p>Default value: <code>100</code></p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>An optional limit for the number of entries returned in a single call.</p>
    /// <p>Default value: <code>100</code></p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    /// <p>Default value: <code>null</code></p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    /// <p>Default value: <code>null</code></p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token specifying which page of results to return in the response. If no token is provided, the default page is the first page.</p>
    /// <p>Default value: <code>null</code></p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The geometry used to filter device positions.</p>
    pub fn filter_geometry(mut self, input: crate::types::TrackingFilterGeometry) -> Self {
        self.filter_geometry = ::std::option::Option::Some(input);
        self
    }
    /// <p>The geometry used to filter device positions.</p>
    pub fn set_filter_geometry(mut self, input: ::std::option::Option<crate::types::TrackingFilterGeometry>) -> Self {
        self.filter_geometry = input;
        self
    }
    /// <p>The geometry used to filter device positions.</p>
    pub fn get_filter_geometry(&self) -> &::std::option::Option<crate::types::TrackingFilterGeometry> {
        &self.filter_geometry
    }
    /// Consumes the builder and constructs a [`ListDevicePositionsInput`](crate::operation::list_device_positions::ListDevicePositionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_device_positions::ListDevicePositionsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_device_positions::ListDevicePositionsInput {
            tracker_name: self.tracker_name,
            max_results: self.max_results,
            next_token: self.next_token,
            filter_geometry: self.filter_geometry,
        })
    }
}
