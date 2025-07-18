// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetGeoMatchSetInput {
    /// <p>The <code>GeoMatchSetId</code> of the <code>GeoMatchSet</code> that you want to get. <code>GeoMatchSetId</code> is returned by <code>CreateGeoMatchSet</code> and by <code>ListGeoMatchSets</code>.</p>
    pub geo_match_set_id: ::std::option::Option<::std::string::String>,
}
impl GetGeoMatchSetInput {
    /// <p>The <code>GeoMatchSetId</code> of the <code>GeoMatchSet</code> that you want to get. <code>GeoMatchSetId</code> is returned by <code>CreateGeoMatchSet</code> and by <code>ListGeoMatchSets</code>.</p>
    pub fn geo_match_set_id(&self) -> ::std::option::Option<&str> {
        self.geo_match_set_id.as_deref()
    }
}
impl GetGeoMatchSetInput {
    /// Creates a new builder-style object to manufacture [`GetGeoMatchSetInput`](crate::operation::get_geo_match_set::GetGeoMatchSetInput).
    pub fn builder() -> crate::operation::get_geo_match_set::builders::GetGeoMatchSetInputBuilder {
        crate::operation::get_geo_match_set::builders::GetGeoMatchSetInputBuilder::default()
    }
}

/// A builder for [`GetGeoMatchSetInput`](crate::operation::get_geo_match_set::GetGeoMatchSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetGeoMatchSetInputBuilder {
    pub(crate) geo_match_set_id: ::std::option::Option<::std::string::String>,
}
impl GetGeoMatchSetInputBuilder {
    /// <p>The <code>GeoMatchSetId</code> of the <code>GeoMatchSet</code> that you want to get. <code>GeoMatchSetId</code> is returned by <code>CreateGeoMatchSet</code> and by <code>ListGeoMatchSets</code>.</p>
    /// This field is required.
    pub fn geo_match_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.geo_match_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>GeoMatchSetId</code> of the <code>GeoMatchSet</code> that you want to get. <code>GeoMatchSetId</code> is returned by <code>CreateGeoMatchSet</code> and by <code>ListGeoMatchSets</code>.</p>
    pub fn set_geo_match_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.geo_match_set_id = input;
        self
    }
    /// <p>The <code>GeoMatchSetId</code> of the <code>GeoMatchSet</code> that you want to get. <code>GeoMatchSetId</code> is returned by <code>CreateGeoMatchSet</code> and by <code>ListGeoMatchSets</code>.</p>
    pub fn get_geo_match_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.geo_match_set_id
    }
    /// Consumes the builder and constructs a [`GetGeoMatchSetInput`](crate::operation::get_geo_match_set::GetGeoMatchSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_geo_match_set::GetGeoMatchSetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_geo_match_set::GetGeoMatchSetInput {
            geo_match_set_id: self.geo_match_set_id,
        })
    }
}
