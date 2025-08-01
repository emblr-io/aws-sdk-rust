// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMultiRegionAccessPointOutput {
    /// <p>A container element containing the details of the requested Multi-Region Access Point.</p>
    pub access_point: ::std::option::Option<crate::types::MultiRegionAccessPointReport>,
    _request_id: Option<String>,
}
impl GetMultiRegionAccessPointOutput {
    /// <p>A container element containing the details of the requested Multi-Region Access Point.</p>
    pub fn access_point(&self) -> ::std::option::Option<&crate::types::MultiRegionAccessPointReport> {
        self.access_point.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetMultiRegionAccessPointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetMultiRegionAccessPointOutput {
    /// Creates a new builder-style object to manufacture [`GetMultiRegionAccessPointOutput`](crate::operation::get_multi_region_access_point::GetMultiRegionAccessPointOutput).
    pub fn builder() -> crate::operation::get_multi_region_access_point::builders::GetMultiRegionAccessPointOutputBuilder {
        crate::operation::get_multi_region_access_point::builders::GetMultiRegionAccessPointOutputBuilder::default()
    }
}

/// A builder for [`GetMultiRegionAccessPointOutput`](crate::operation::get_multi_region_access_point::GetMultiRegionAccessPointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMultiRegionAccessPointOutputBuilder {
    pub(crate) access_point: ::std::option::Option<crate::types::MultiRegionAccessPointReport>,
    _request_id: Option<String>,
}
impl GetMultiRegionAccessPointOutputBuilder {
    /// <p>A container element containing the details of the requested Multi-Region Access Point.</p>
    pub fn access_point(mut self, input: crate::types::MultiRegionAccessPointReport) -> Self {
        self.access_point = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container element containing the details of the requested Multi-Region Access Point.</p>
    pub fn set_access_point(mut self, input: ::std::option::Option<crate::types::MultiRegionAccessPointReport>) -> Self {
        self.access_point = input;
        self
    }
    /// <p>A container element containing the details of the requested Multi-Region Access Point.</p>
    pub fn get_access_point(&self) -> &::std::option::Option<crate::types::MultiRegionAccessPointReport> {
        &self.access_point
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetMultiRegionAccessPointOutput`](crate::operation::get_multi_region_access_point::GetMultiRegionAccessPointOutput).
    pub fn build(self) -> crate::operation::get_multi_region_access_point::GetMultiRegionAccessPointOutput {
        crate::operation::get_multi_region_access_point::GetMultiRegionAccessPointOutput {
            access_point: self.access_point,
            _request_id: self._request_id,
        }
    }
}
