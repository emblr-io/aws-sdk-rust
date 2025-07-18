// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetGeoMatchSetOutput {
    /// <p>Information about the <code>GeoMatchSet</code> that you specified in the <code>GetGeoMatchSet</code> request. This includes the <code>Type</code>, which for a <code>GeoMatchContraint</code> is always <code>Country</code>, as well as the <code>Value</code>, which is the identifier for a specific country.</p>
    pub geo_match_set: ::std::option::Option<crate::types::GeoMatchSet>,
    _request_id: Option<String>,
}
impl GetGeoMatchSetOutput {
    /// <p>Information about the <code>GeoMatchSet</code> that you specified in the <code>GetGeoMatchSet</code> request. This includes the <code>Type</code>, which for a <code>GeoMatchContraint</code> is always <code>Country</code>, as well as the <code>Value</code>, which is the identifier for a specific country.</p>
    pub fn geo_match_set(&self) -> ::std::option::Option<&crate::types::GeoMatchSet> {
        self.geo_match_set.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetGeoMatchSetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetGeoMatchSetOutput {
    /// Creates a new builder-style object to manufacture [`GetGeoMatchSetOutput`](crate::operation::get_geo_match_set::GetGeoMatchSetOutput).
    pub fn builder() -> crate::operation::get_geo_match_set::builders::GetGeoMatchSetOutputBuilder {
        crate::operation::get_geo_match_set::builders::GetGeoMatchSetOutputBuilder::default()
    }
}

/// A builder for [`GetGeoMatchSetOutput`](crate::operation::get_geo_match_set::GetGeoMatchSetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetGeoMatchSetOutputBuilder {
    pub(crate) geo_match_set: ::std::option::Option<crate::types::GeoMatchSet>,
    _request_id: Option<String>,
}
impl GetGeoMatchSetOutputBuilder {
    /// <p>Information about the <code>GeoMatchSet</code> that you specified in the <code>GetGeoMatchSet</code> request. This includes the <code>Type</code>, which for a <code>GeoMatchContraint</code> is always <code>Country</code>, as well as the <code>Value</code>, which is the identifier for a specific country.</p>
    pub fn geo_match_set(mut self, input: crate::types::GeoMatchSet) -> Self {
        self.geo_match_set = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the <code>GeoMatchSet</code> that you specified in the <code>GetGeoMatchSet</code> request. This includes the <code>Type</code>, which for a <code>GeoMatchContraint</code> is always <code>Country</code>, as well as the <code>Value</code>, which is the identifier for a specific country.</p>
    pub fn set_geo_match_set(mut self, input: ::std::option::Option<crate::types::GeoMatchSet>) -> Self {
        self.geo_match_set = input;
        self
    }
    /// <p>Information about the <code>GeoMatchSet</code> that you specified in the <code>GetGeoMatchSet</code> request. This includes the <code>Type</code>, which for a <code>GeoMatchContraint</code> is always <code>Country</code>, as well as the <code>Value</code>, which is the identifier for a specific country.</p>
    pub fn get_geo_match_set(&self) -> &::std::option::Option<crate::types::GeoMatchSet> {
        &self.geo_match_set
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetGeoMatchSetOutput`](crate::operation::get_geo_match_set::GetGeoMatchSetOutput).
    pub fn build(self) -> crate::operation::get_geo_match_set::GetGeoMatchSetOutput {
        crate::operation::get_geo_match_set::GetGeoMatchSetOutput {
            geo_match_set: self.geo_match_set,
            _request_id: self._request_id,
        }
    }
}
