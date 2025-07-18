// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInterpolatedAssetPropertyValuesOutput {
    /// <p>The requested interpolated values.</p>
    pub interpolated_asset_property_values: ::std::vec::Vec<crate::types::InterpolatedAssetPropertyValue>,
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetInterpolatedAssetPropertyValuesOutput {
    /// <p>The requested interpolated values.</p>
    pub fn interpolated_asset_property_values(&self) -> &[crate::types::InterpolatedAssetPropertyValue] {
        use std::ops::Deref;
        self.interpolated_asset_property_values.deref()
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetInterpolatedAssetPropertyValuesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetInterpolatedAssetPropertyValuesOutput {
    /// Creates a new builder-style object to manufacture [`GetInterpolatedAssetPropertyValuesOutput`](crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesOutput).
    pub fn builder() -> crate::operation::get_interpolated_asset_property_values::builders::GetInterpolatedAssetPropertyValuesOutputBuilder {
        crate::operation::get_interpolated_asset_property_values::builders::GetInterpolatedAssetPropertyValuesOutputBuilder::default()
    }
}

/// A builder for [`GetInterpolatedAssetPropertyValuesOutput`](crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetInterpolatedAssetPropertyValuesOutputBuilder {
    pub(crate) interpolated_asset_property_values: ::std::option::Option<::std::vec::Vec<crate::types::InterpolatedAssetPropertyValue>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetInterpolatedAssetPropertyValuesOutputBuilder {
    /// Appends an item to `interpolated_asset_property_values`.
    ///
    /// To override the contents of this collection use [`set_interpolated_asset_property_values`](Self::set_interpolated_asset_property_values).
    ///
    /// <p>The requested interpolated values.</p>
    pub fn interpolated_asset_property_values(mut self, input: crate::types::InterpolatedAssetPropertyValue) -> Self {
        let mut v = self.interpolated_asset_property_values.unwrap_or_default();
        v.push(input);
        self.interpolated_asset_property_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The requested interpolated values.</p>
    pub fn set_interpolated_asset_property_values(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::InterpolatedAssetPropertyValue>>,
    ) -> Self {
        self.interpolated_asset_property_values = input;
        self
    }
    /// <p>The requested interpolated values.</p>
    pub fn get_interpolated_asset_property_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InterpolatedAssetPropertyValue>> {
        &self.interpolated_asset_property_values
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetInterpolatedAssetPropertyValuesOutput`](crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`interpolated_asset_property_values`](crate::operation::get_interpolated_asset_property_values::builders::GetInterpolatedAssetPropertyValuesOutputBuilder::interpolated_asset_property_values)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_interpolated_asset_property_values::GetInterpolatedAssetPropertyValuesOutput {
                interpolated_asset_property_values: self.interpolated_asset_property_values
                    .ok_or_else(||
                        ::aws_smithy_types::error::operation::BuildError::missing_field("interpolated_asset_property_values", "interpolated_asset_property_values was not specified but it is required when building GetInterpolatedAssetPropertyValuesOutput")
                    )?
                ,
                next_token: self.next_token
                ,
                _request_id: self._request_id,
            }
        )
    }
}
