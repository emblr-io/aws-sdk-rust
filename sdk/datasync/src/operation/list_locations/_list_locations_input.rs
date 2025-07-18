// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>ListLocationsRequest</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLocationsInput {
    /// <p>The maximum number of locations to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>An opaque string that indicates the position at which to begin the next list of locations.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>You can use API filters to narrow down the list of resources returned by <code>ListLocations</code>. For example, to retrieve all tasks on a specific source location, you can use <code>ListLocations</code> with filter name <code>LocationType S3</code> and <code>Operator Equals</code>.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::LocationFilter>>,
}
impl ListLocationsInput {
    /// <p>The maximum number of locations to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>An opaque string that indicates the position at which to begin the next list of locations.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>You can use API filters to narrow down the list of resources returned by <code>ListLocations</code>. For example, to retrieve all tasks on a specific source location, you can use <code>ListLocations</code> with filter name <code>LocationType S3</code> and <code>Operator Equals</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::LocationFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
}
impl ListLocationsInput {
    /// Creates a new builder-style object to manufacture [`ListLocationsInput`](crate::operation::list_locations::ListLocationsInput).
    pub fn builder() -> crate::operation::list_locations::builders::ListLocationsInputBuilder {
        crate::operation::list_locations::builders::ListLocationsInputBuilder::default()
    }
}

/// A builder for [`ListLocationsInput`](crate::operation::list_locations::ListLocationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLocationsInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::LocationFilter>>,
}
impl ListLocationsInputBuilder {
    /// <p>The maximum number of locations to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of locations to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of locations to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>An opaque string that indicates the position at which to begin the next list of locations.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An opaque string that indicates the position at which to begin the next list of locations.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An opaque string that indicates the position at which to begin the next list of locations.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>You can use API filters to narrow down the list of resources returned by <code>ListLocations</code>. For example, to retrieve all tasks on a specific source location, you can use <code>ListLocations</code> with filter name <code>LocationType S3</code> and <code>Operator Equals</code>.</p>
    pub fn filters(mut self, input: crate::types::LocationFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can use API filters to narrow down the list of resources returned by <code>ListLocations</code>. For example, to retrieve all tasks on a specific source location, you can use <code>ListLocations</code> with filter name <code>LocationType S3</code> and <code>Operator Equals</code>.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LocationFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>You can use API filters to narrow down the list of resources returned by <code>ListLocations</code>. For example, to retrieve all tasks on a specific source location, you can use <code>ListLocations</code> with filter name <code>LocationType S3</code> and <code>Operator Equals</code>.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LocationFilter>> {
        &self.filters
    }
    /// Consumes the builder and constructs a [`ListLocationsInput`](crate::operation::list_locations::ListLocationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_locations::ListLocationsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_locations::ListLocationsInput {
            max_results: self.max_results,
            next_token: self.next_token,
            filters: self.filters,
        })
    }
}
