// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A container for the response details that are returned when querying about an asynchronous request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AsyncResponseDetails {
    /// <p>The details for the Multi-Region Access Point.</p>
    pub multi_region_access_point_details: ::std::option::Option<crate::types::MultiRegionAccessPointsAsyncResponse>,
    /// <p>Error details for an asynchronous request.</p>
    pub error_details: ::std::option::Option<crate::types::AsyncErrorDetails>,
}
impl AsyncResponseDetails {
    /// <p>The details for the Multi-Region Access Point.</p>
    pub fn multi_region_access_point_details(&self) -> ::std::option::Option<&crate::types::MultiRegionAccessPointsAsyncResponse> {
        self.multi_region_access_point_details.as_ref()
    }
    /// <p>Error details for an asynchronous request.</p>
    pub fn error_details(&self) -> ::std::option::Option<&crate::types::AsyncErrorDetails> {
        self.error_details.as_ref()
    }
}
impl AsyncResponseDetails {
    /// Creates a new builder-style object to manufacture [`AsyncResponseDetails`](crate::types::AsyncResponseDetails).
    pub fn builder() -> crate::types::builders::AsyncResponseDetailsBuilder {
        crate::types::builders::AsyncResponseDetailsBuilder::default()
    }
}

/// A builder for [`AsyncResponseDetails`](crate::types::AsyncResponseDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AsyncResponseDetailsBuilder {
    pub(crate) multi_region_access_point_details: ::std::option::Option<crate::types::MultiRegionAccessPointsAsyncResponse>,
    pub(crate) error_details: ::std::option::Option<crate::types::AsyncErrorDetails>,
}
impl AsyncResponseDetailsBuilder {
    /// <p>The details for the Multi-Region Access Point.</p>
    pub fn multi_region_access_point_details(mut self, input: crate::types::MultiRegionAccessPointsAsyncResponse) -> Self {
        self.multi_region_access_point_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details for the Multi-Region Access Point.</p>
    pub fn set_multi_region_access_point_details(mut self, input: ::std::option::Option<crate::types::MultiRegionAccessPointsAsyncResponse>) -> Self {
        self.multi_region_access_point_details = input;
        self
    }
    /// <p>The details for the Multi-Region Access Point.</p>
    pub fn get_multi_region_access_point_details(&self) -> &::std::option::Option<crate::types::MultiRegionAccessPointsAsyncResponse> {
        &self.multi_region_access_point_details
    }
    /// <p>Error details for an asynchronous request.</p>
    pub fn error_details(mut self, input: crate::types::AsyncErrorDetails) -> Self {
        self.error_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Error details for an asynchronous request.</p>
    pub fn set_error_details(mut self, input: ::std::option::Option<crate::types::AsyncErrorDetails>) -> Self {
        self.error_details = input;
        self
    }
    /// <p>Error details for an asynchronous request.</p>
    pub fn get_error_details(&self) -> &::std::option::Option<crate::types::AsyncErrorDetails> {
        &self.error_details
    }
    /// Consumes the builder and constructs a [`AsyncResponseDetails`](crate::types::AsyncResponseDetails).
    pub fn build(self) -> crate::types::AsyncResponseDetails {
        crate::types::AsyncResponseDetails {
            multi_region_access_point_details: self.multi_region_access_point_details,
            error_details: self.error_details,
        }
    }
}
