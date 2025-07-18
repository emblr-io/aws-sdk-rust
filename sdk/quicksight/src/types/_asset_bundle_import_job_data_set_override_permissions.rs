// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains a list of permissions to be applied to a list of dataset IDs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssetBundleImportJobDataSetOverridePermissions {
    /// <p>A list of dataset IDs that you want to apply overrides to. You can use <code>*</code> to override all datasets in this asset bundle.</p>
    pub data_set_ids: ::std::vec::Vec<::std::string::String>,
    /// <p>A list of permissions for the datasets that you want to apply overrides to.</p>
    pub permissions: ::std::option::Option<crate::types::AssetBundleResourcePermissions>,
}
impl AssetBundleImportJobDataSetOverridePermissions {
    /// <p>A list of dataset IDs that you want to apply overrides to. You can use <code>*</code> to override all datasets in this asset bundle.</p>
    pub fn data_set_ids(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.data_set_ids.deref()
    }
    /// <p>A list of permissions for the datasets that you want to apply overrides to.</p>
    pub fn permissions(&self) -> ::std::option::Option<&crate::types::AssetBundleResourcePermissions> {
        self.permissions.as_ref()
    }
}
impl AssetBundleImportJobDataSetOverridePermissions {
    /// Creates a new builder-style object to manufacture [`AssetBundleImportJobDataSetOverridePermissions`](crate::types::AssetBundleImportJobDataSetOverridePermissions).
    pub fn builder() -> crate::types::builders::AssetBundleImportJobDataSetOverridePermissionsBuilder {
        crate::types::builders::AssetBundleImportJobDataSetOverridePermissionsBuilder::default()
    }
}

/// A builder for [`AssetBundleImportJobDataSetOverridePermissions`](crate::types::AssetBundleImportJobDataSetOverridePermissions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssetBundleImportJobDataSetOverridePermissionsBuilder {
    pub(crate) data_set_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) permissions: ::std::option::Option<crate::types::AssetBundleResourcePermissions>,
}
impl AssetBundleImportJobDataSetOverridePermissionsBuilder {
    /// Appends an item to `data_set_ids`.
    ///
    /// To override the contents of this collection use [`set_data_set_ids`](Self::set_data_set_ids).
    ///
    /// <p>A list of dataset IDs that you want to apply overrides to. You can use <code>*</code> to override all datasets in this asset bundle.</p>
    pub fn data_set_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.data_set_ids.unwrap_or_default();
        v.push(input.into());
        self.data_set_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of dataset IDs that you want to apply overrides to. You can use <code>*</code> to override all datasets in this asset bundle.</p>
    pub fn set_data_set_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.data_set_ids = input;
        self
    }
    /// <p>A list of dataset IDs that you want to apply overrides to. You can use <code>*</code> to override all datasets in this asset bundle.</p>
    pub fn get_data_set_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.data_set_ids
    }
    /// <p>A list of permissions for the datasets that you want to apply overrides to.</p>
    /// This field is required.
    pub fn permissions(mut self, input: crate::types::AssetBundleResourcePermissions) -> Self {
        self.permissions = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of permissions for the datasets that you want to apply overrides to.</p>
    pub fn set_permissions(mut self, input: ::std::option::Option<crate::types::AssetBundleResourcePermissions>) -> Self {
        self.permissions = input;
        self
    }
    /// <p>A list of permissions for the datasets that you want to apply overrides to.</p>
    pub fn get_permissions(&self) -> &::std::option::Option<crate::types::AssetBundleResourcePermissions> {
        &self.permissions
    }
    /// Consumes the builder and constructs a [`AssetBundleImportJobDataSetOverridePermissions`](crate::types::AssetBundleImportJobDataSetOverridePermissions).
    /// This method will fail if any of the following fields are not set:
    /// - [`data_set_ids`](crate::types::builders::AssetBundleImportJobDataSetOverridePermissionsBuilder::data_set_ids)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::AssetBundleImportJobDataSetOverridePermissions, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AssetBundleImportJobDataSetOverridePermissions {
            data_set_ids: self.data_set_ids.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_set_ids",
                    "data_set_ids was not specified but it is required when building AssetBundleImportJobDataSetOverridePermissions",
                )
            })?,
            permissions: self.permissions,
        })
    }
}
