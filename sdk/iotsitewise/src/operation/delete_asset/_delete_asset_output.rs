// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAssetOutput {
    /// <p>The status of the asset, which contains a state (<code>DELETING</code> after successfully calling this operation) and any error message.</p>
    pub asset_status: ::std::option::Option<crate::types::AssetStatus>,
    _request_id: Option<String>,
}
impl DeleteAssetOutput {
    /// <p>The status of the asset, which contains a state (<code>DELETING</code> after successfully calling this operation) and any error message.</p>
    pub fn asset_status(&self) -> ::std::option::Option<&crate::types::AssetStatus> {
        self.asset_status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteAssetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteAssetOutput {
    /// Creates a new builder-style object to manufacture [`DeleteAssetOutput`](crate::operation::delete_asset::DeleteAssetOutput).
    pub fn builder() -> crate::operation::delete_asset::builders::DeleteAssetOutputBuilder {
        crate::operation::delete_asset::builders::DeleteAssetOutputBuilder::default()
    }
}

/// A builder for [`DeleteAssetOutput`](crate::operation::delete_asset::DeleteAssetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAssetOutputBuilder {
    pub(crate) asset_status: ::std::option::Option<crate::types::AssetStatus>,
    _request_id: Option<String>,
}
impl DeleteAssetOutputBuilder {
    /// <p>The status of the asset, which contains a state (<code>DELETING</code> after successfully calling this operation) and any error message.</p>
    /// This field is required.
    pub fn asset_status(mut self, input: crate::types::AssetStatus) -> Self {
        self.asset_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the asset, which contains a state (<code>DELETING</code> after successfully calling this operation) and any error message.</p>
    pub fn set_asset_status(mut self, input: ::std::option::Option<crate::types::AssetStatus>) -> Self {
        self.asset_status = input;
        self
    }
    /// <p>The status of the asset, which contains a state (<code>DELETING</code> after successfully calling this operation) and any error message.</p>
    pub fn get_asset_status(&self) -> &::std::option::Option<crate::types::AssetStatus> {
        &self.asset_status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteAssetOutput`](crate::operation::delete_asset::DeleteAssetOutput).
    pub fn build(self) -> crate::operation::delete_asset::DeleteAssetOutput {
        crate::operation::delete_asset::DeleteAssetOutput {
            asset_status: self.asset_status,
            _request_id: self._request_id,
        }
    }
}
