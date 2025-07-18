// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains the permissions for the resource that you want to override in an asset bundle import job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssetBundleResourcePermissions {
    /// <p>A list of principals to grant permissions on.</p>
    pub principals: ::std::vec::Vec<::std::string::String>,
    /// <p>A list of IAM actions to grant permissions on.</p>
    pub actions: ::std::vec::Vec<::std::string::String>,
}
impl AssetBundleResourcePermissions {
    /// <p>A list of principals to grant permissions on.</p>
    pub fn principals(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.principals.deref()
    }
    /// <p>A list of IAM actions to grant permissions on.</p>
    pub fn actions(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.actions.deref()
    }
}
impl AssetBundleResourcePermissions {
    /// Creates a new builder-style object to manufacture [`AssetBundleResourcePermissions`](crate::types::AssetBundleResourcePermissions).
    pub fn builder() -> crate::types::builders::AssetBundleResourcePermissionsBuilder {
        crate::types::builders::AssetBundleResourcePermissionsBuilder::default()
    }
}

/// A builder for [`AssetBundleResourcePermissions`](crate::types::AssetBundleResourcePermissions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssetBundleResourcePermissionsBuilder {
    pub(crate) principals: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) actions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AssetBundleResourcePermissionsBuilder {
    /// Appends an item to `principals`.
    ///
    /// To override the contents of this collection use [`set_principals`](Self::set_principals).
    ///
    /// <p>A list of principals to grant permissions on.</p>
    pub fn principals(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.principals.unwrap_or_default();
        v.push(input.into());
        self.principals = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of principals to grant permissions on.</p>
    pub fn set_principals(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.principals = input;
        self
    }
    /// <p>A list of principals to grant permissions on.</p>
    pub fn get_principals(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.principals
    }
    /// Appends an item to `actions`.
    ///
    /// To override the contents of this collection use [`set_actions`](Self::set_actions).
    ///
    /// <p>A list of IAM actions to grant permissions on.</p>
    pub fn actions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.actions.unwrap_or_default();
        v.push(input.into());
        self.actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of IAM actions to grant permissions on.</p>
    pub fn set_actions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.actions = input;
        self
    }
    /// <p>A list of IAM actions to grant permissions on.</p>
    pub fn get_actions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.actions
    }
    /// Consumes the builder and constructs a [`AssetBundleResourcePermissions`](crate::types::AssetBundleResourcePermissions).
    /// This method will fail if any of the following fields are not set:
    /// - [`principals`](crate::types::builders::AssetBundleResourcePermissionsBuilder::principals)
    /// - [`actions`](crate::types::builders::AssetBundleResourcePermissionsBuilder::actions)
    pub fn build(self) -> ::std::result::Result<crate::types::AssetBundleResourcePermissions, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AssetBundleResourcePermissions {
            principals: self.principals.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "principals",
                    "principals was not specified but it is required when building AssetBundleResourcePermissions",
                )
            })?,
            actions: self.actions.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "actions",
                    "actions was not specified but it is required when building AssetBundleResourcePermissions",
                )
            })?,
        })
    }
}
