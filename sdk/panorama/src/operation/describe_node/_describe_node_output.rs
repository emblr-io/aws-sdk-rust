// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeNodeOutput {
    /// <p>The node's ID.</p>
    pub node_id: ::std::string::String,
    /// <p>The node's name.</p>
    pub name: ::std::string::String,
    /// <p>The node's category.</p>
    pub category: crate::types::NodeCategory,
    /// <p>The account ID of the node's owner.</p>
    pub owner_account: ::std::string::String,
    /// <p>The node's package name.</p>
    pub package_name: ::std::string::String,
    /// <p>The node's package ID.</p>
    pub package_id: ::std::string::String,
    /// <p>The node's ARN.</p>
    pub package_arn: ::std::option::Option<::std::string::String>,
    /// <p>The node's package version.</p>
    pub package_version: ::std::string::String,
    /// <p>The node's patch version.</p>
    pub patch_version: ::std::string::String,
    /// <p>The node's interface.</p>
    pub node_interface: ::std::option::Option<crate::types::NodeInterface>,
    /// <p>The node's asset name.</p>
    pub asset_name: ::std::option::Option<::std::string::String>,
    /// <p>The node's description.</p>
    pub description: ::std::string::String,
    /// <p>When the node was created.</p>
    pub created_time: ::aws_smithy_types::DateTime,
    /// <p>When the node was updated.</p>
    pub last_updated_time: ::aws_smithy_types::DateTime,
    _request_id: Option<String>,
}
impl DescribeNodeOutput {
    /// <p>The node's ID.</p>
    pub fn node_id(&self) -> &str {
        use std::ops::Deref;
        self.node_id.deref()
    }
    /// <p>The node's name.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The node's category.</p>
    pub fn category(&self) -> &crate::types::NodeCategory {
        &self.category
    }
    /// <p>The account ID of the node's owner.</p>
    pub fn owner_account(&self) -> &str {
        use std::ops::Deref;
        self.owner_account.deref()
    }
    /// <p>The node's package name.</p>
    pub fn package_name(&self) -> &str {
        use std::ops::Deref;
        self.package_name.deref()
    }
    /// <p>The node's package ID.</p>
    pub fn package_id(&self) -> &str {
        use std::ops::Deref;
        self.package_id.deref()
    }
    /// <p>The node's ARN.</p>
    pub fn package_arn(&self) -> ::std::option::Option<&str> {
        self.package_arn.as_deref()
    }
    /// <p>The node's package version.</p>
    pub fn package_version(&self) -> &str {
        use std::ops::Deref;
        self.package_version.deref()
    }
    /// <p>The node's patch version.</p>
    pub fn patch_version(&self) -> &str {
        use std::ops::Deref;
        self.patch_version.deref()
    }
    /// <p>The node's interface.</p>
    pub fn node_interface(&self) -> ::std::option::Option<&crate::types::NodeInterface> {
        self.node_interface.as_ref()
    }
    /// <p>The node's asset name.</p>
    pub fn asset_name(&self) -> ::std::option::Option<&str> {
        self.asset_name.as_deref()
    }
    /// <p>The node's description.</p>
    pub fn description(&self) -> &str {
        use std::ops::Deref;
        self.description.deref()
    }
    /// <p>When the node was created.</p>
    pub fn created_time(&self) -> &::aws_smithy_types::DateTime {
        &self.created_time
    }
    /// <p>When the node was updated.</p>
    pub fn last_updated_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_updated_time
    }
}
impl ::aws_types::request_id::RequestId for DescribeNodeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeNodeOutput {
    /// Creates a new builder-style object to manufacture [`DescribeNodeOutput`](crate::operation::describe_node::DescribeNodeOutput).
    pub fn builder() -> crate::operation::describe_node::builders::DescribeNodeOutputBuilder {
        crate::operation::describe_node::builders::DescribeNodeOutputBuilder::default()
    }
}

/// A builder for [`DescribeNodeOutput`](crate::operation::describe_node::DescribeNodeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeNodeOutputBuilder {
    pub(crate) node_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) category: ::std::option::Option<crate::types::NodeCategory>,
    pub(crate) owner_account: ::std::option::Option<::std::string::String>,
    pub(crate) package_name: ::std::option::Option<::std::string::String>,
    pub(crate) package_id: ::std::option::Option<::std::string::String>,
    pub(crate) package_arn: ::std::option::Option<::std::string::String>,
    pub(crate) package_version: ::std::option::Option<::std::string::String>,
    pub(crate) patch_version: ::std::option::Option<::std::string::String>,
    pub(crate) node_interface: ::std::option::Option<crate::types::NodeInterface>,
    pub(crate) asset_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeNodeOutputBuilder {
    /// <p>The node's ID.</p>
    /// This field is required.
    pub fn node_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node's ID.</p>
    pub fn set_node_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node_id = input;
        self
    }
    /// <p>The node's ID.</p>
    pub fn get_node_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.node_id
    }
    /// <p>The node's name.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node's name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The node's name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The node's category.</p>
    /// This field is required.
    pub fn category(mut self, input: crate::types::NodeCategory) -> Self {
        self.category = ::std::option::Option::Some(input);
        self
    }
    /// <p>The node's category.</p>
    pub fn set_category(mut self, input: ::std::option::Option<crate::types::NodeCategory>) -> Self {
        self.category = input;
        self
    }
    /// <p>The node's category.</p>
    pub fn get_category(&self) -> &::std::option::Option<crate::types::NodeCategory> {
        &self.category
    }
    /// <p>The account ID of the node's owner.</p>
    /// This field is required.
    pub fn owner_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID of the node's owner.</p>
    pub fn set_owner_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_account = input;
        self
    }
    /// <p>The account ID of the node's owner.</p>
    pub fn get_owner_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_account
    }
    /// <p>The node's package name.</p>
    /// This field is required.
    pub fn package_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node's package name.</p>
    pub fn set_package_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_name = input;
        self
    }
    /// <p>The node's package name.</p>
    pub fn get_package_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_name
    }
    /// <p>The node's package ID.</p>
    /// This field is required.
    pub fn package_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node's package ID.</p>
    pub fn set_package_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_id = input;
        self
    }
    /// <p>The node's package ID.</p>
    pub fn get_package_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_id
    }
    /// <p>The node's ARN.</p>
    pub fn package_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node's ARN.</p>
    pub fn set_package_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_arn = input;
        self
    }
    /// <p>The node's ARN.</p>
    pub fn get_package_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_arn
    }
    /// <p>The node's package version.</p>
    /// This field is required.
    pub fn package_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node's package version.</p>
    pub fn set_package_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_version = input;
        self
    }
    /// <p>The node's package version.</p>
    pub fn get_package_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_version
    }
    /// <p>The node's patch version.</p>
    /// This field is required.
    pub fn patch_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.patch_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node's patch version.</p>
    pub fn set_patch_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.patch_version = input;
        self
    }
    /// <p>The node's patch version.</p>
    pub fn get_patch_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.patch_version
    }
    /// <p>The node's interface.</p>
    /// This field is required.
    pub fn node_interface(mut self, input: crate::types::NodeInterface) -> Self {
        self.node_interface = ::std::option::Option::Some(input);
        self
    }
    /// <p>The node's interface.</p>
    pub fn set_node_interface(mut self, input: ::std::option::Option<crate::types::NodeInterface>) -> Self {
        self.node_interface = input;
        self
    }
    /// <p>The node's interface.</p>
    pub fn get_node_interface(&self) -> &::std::option::Option<crate::types::NodeInterface> {
        &self.node_interface
    }
    /// <p>The node's asset name.</p>
    pub fn asset_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node's asset name.</p>
    pub fn set_asset_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_name = input;
        self
    }
    /// <p>The node's asset name.</p>
    pub fn get_asset_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_name
    }
    /// <p>The node's description.</p>
    /// This field is required.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node's description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The node's description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>When the node was created.</p>
    /// This field is required.
    pub fn created_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the node was created.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>When the node was created.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time
    }
    /// <p>When the node was updated.</p>
    /// This field is required.
    pub fn last_updated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the node was updated.</p>
    pub fn set_last_updated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_time = input;
        self
    }
    /// <p>When the node was updated.</p>
    pub fn get_last_updated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeNodeOutput`](crate::operation::describe_node::DescribeNodeOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`node_id`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::node_id)
    /// - [`name`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::name)
    /// - [`category`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::category)
    /// - [`owner_account`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::owner_account)
    /// - [`package_name`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::package_name)
    /// - [`package_id`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::package_id)
    /// - [`package_version`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::package_version)
    /// - [`patch_version`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::patch_version)
    /// - [`description`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::description)
    /// - [`created_time`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::created_time)
    /// - [`last_updated_time`](crate::operation::describe_node::builders::DescribeNodeOutputBuilder::last_updated_time)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_node::DescribeNodeOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_node::DescribeNodeOutput {
            node_id: self.node_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "node_id",
                    "node_id was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            category: self.category.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "category",
                    "category was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            owner_account: self.owner_account.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "owner_account",
                    "owner_account was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            package_name: self.package_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "package_name",
                    "package_name was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            package_id: self.package_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "package_id",
                    "package_id was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            package_arn: self.package_arn,
            package_version: self.package_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "package_version",
                    "package_version was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            patch_version: self.patch_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "patch_version",
                    "patch_version was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            node_interface: self.node_interface,
            asset_name: self.asset_name,
            description: self.description.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "description",
                    "description was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            created_time: self.created_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_time",
                    "created_time was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            last_updated_time: self.last_updated_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_updated_time",
                    "last_updated_time was not specified but it is required when building DescribeNodeOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
