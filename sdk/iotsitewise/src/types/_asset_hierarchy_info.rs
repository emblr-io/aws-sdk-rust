// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a parent asset and a child asset that are related through an asset hierarchy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssetHierarchyInfo {
    /// <p>The ID of the parent asset in this asset relationship.</p>
    pub parent_asset_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the child asset in this asset relationship.</p>
    pub child_asset_id: ::std::option::Option<::std::string::String>,
}
impl AssetHierarchyInfo {
    /// <p>The ID of the parent asset in this asset relationship.</p>
    pub fn parent_asset_id(&self) -> ::std::option::Option<&str> {
        self.parent_asset_id.as_deref()
    }
    /// <p>The ID of the child asset in this asset relationship.</p>
    pub fn child_asset_id(&self) -> ::std::option::Option<&str> {
        self.child_asset_id.as_deref()
    }
}
impl AssetHierarchyInfo {
    /// Creates a new builder-style object to manufacture [`AssetHierarchyInfo`](crate::types::AssetHierarchyInfo).
    pub fn builder() -> crate::types::builders::AssetHierarchyInfoBuilder {
        crate::types::builders::AssetHierarchyInfoBuilder::default()
    }
}

/// A builder for [`AssetHierarchyInfo`](crate::types::AssetHierarchyInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssetHierarchyInfoBuilder {
    pub(crate) parent_asset_id: ::std::option::Option<::std::string::String>,
    pub(crate) child_asset_id: ::std::option::Option<::std::string::String>,
}
impl AssetHierarchyInfoBuilder {
    /// <p>The ID of the parent asset in this asset relationship.</p>
    pub fn parent_asset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_asset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the parent asset in this asset relationship.</p>
    pub fn set_parent_asset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_asset_id = input;
        self
    }
    /// <p>The ID of the parent asset in this asset relationship.</p>
    pub fn get_parent_asset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_asset_id
    }
    /// <p>The ID of the child asset in this asset relationship.</p>
    pub fn child_asset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.child_asset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the child asset in this asset relationship.</p>
    pub fn set_child_asset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.child_asset_id = input;
        self
    }
    /// <p>The ID of the child asset in this asset relationship.</p>
    pub fn get_child_asset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.child_asset_id
    }
    /// Consumes the builder and constructs a [`AssetHierarchyInfo`](crate::types::AssetHierarchyInfo).
    pub fn build(self) -> crate::types::AssetHierarchyInfo {
        crate::types::AssetHierarchyInfo {
            parent_asset_id: self.parent_asset_id,
            child_asset_id: self.child_asset_id,
        }
    }
}
