// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Multi-Region Access Point details that are returned when querying about an asynchronous request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MultiRegionAccessPointsAsyncResponse {
    /// <p>A collection of status information for the different Regions that a Multi-Region Access Point supports.</p>
    pub regions: ::std::option::Option<::std::vec::Vec<crate::types::MultiRegionAccessPointRegionalResponse>>,
}
impl MultiRegionAccessPointsAsyncResponse {
    /// <p>A collection of status information for the different Regions that a Multi-Region Access Point supports.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.regions.is_none()`.
    pub fn regions(&self) -> &[crate::types::MultiRegionAccessPointRegionalResponse] {
        self.regions.as_deref().unwrap_or_default()
    }
}
impl MultiRegionAccessPointsAsyncResponse {
    /// Creates a new builder-style object to manufacture [`MultiRegionAccessPointsAsyncResponse`](crate::types::MultiRegionAccessPointsAsyncResponse).
    pub fn builder() -> crate::types::builders::MultiRegionAccessPointsAsyncResponseBuilder {
        crate::types::builders::MultiRegionAccessPointsAsyncResponseBuilder::default()
    }
}

/// A builder for [`MultiRegionAccessPointsAsyncResponse`](crate::types::MultiRegionAccessPointsAsyncResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MultiRegionAccessPointsAsyncResponseBuilder {
    pub(crate) regions: ::std::option::Option<::std::vec::Vec<crate::types::MultiRegionAccessPointRegionalResponse>>,
}
impl MultiRegionAccessPointsAsyncResponseBuilder {
    /// Appends an item to `regions`.
    ///
    /// To override the contents of this collection use [`set_regions`](Self::set_regions).
    ///
    /// <p>A collection of status information for the different Regions that a Multi-Region Access Point supports.</p>
    pub fn regions(mut self, input: crate::types::MultiRegionAccessPointRegionalResponse) -> Self {
        let mut v = self.regions.unwrap_or_default();
        v.push(input);
        self.regions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A collection of status information for the different Regions that a Multi-Region Access Point supports.</p>
    pub fn set_regions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MultiRegionAccessPointRegionalResponse>>) -> Self {
        self.regions = input;
        self
    }
    /// <p>A collection of status information for the different Regions that a Multi-Region Access Point supports.</p>
    pub fn get_regions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MultiRegionAccessPointRegionalResponse>> {
        &self.regions
    }
    /// Consumes the builder and constructs a [`MultiRegionAccessPointsAsyncResponse`](crate::types::MultiRegionAccessPointsAsyncResponse).
    pub fn build(self) -> crate::types::MultiRegionAccessPointsAsyncResponse {
        crate::types::MultiRegionAccessPointsAsyncResponse { regions: self.regions }
    }
}
