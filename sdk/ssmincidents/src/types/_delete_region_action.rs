// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines the information about the Amazon Web Services Region you're deleting from your replication set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRegionAction {
    /// <p>The name of the Amazon Web Services Region you're deleting from the replication set.</p>
    pub region_name: ::std::string::String,
}
impl DeleteRegionAction {
    /// <p>The name of the Amazon Web Services Region you're deleting from the replication set.</p>
    pub fn region_name(&self) -> &str {
        use std::ops::Deref;
        self.region_name.deref()
    }
}
impl DeleteRegionAction {
    /// Creates a new builder-style object to manufacture [`DeleteRegionAction`](crate::types::DeleteRegionAction).
    pub fn builder() -> crate::types::builders::DeleteRegionActionBuilder {
        crate::types::builders::DeleteRegionActionBuilder::default()
    }
}

/// A builder for [`DeleteRegionAction`](crate::types::DeleteRegionAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRegionActionBuilder {
    pub(crate) region_name: ::std::option::Option<::std::string::String>,
}
impl DeleteRegionActionBuilder {
    /// <p>The name of the Amazon Web Services Region you're deleting from the replication set.</p>
    /// This field is required.
    pub fn region_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon Web Services Region you're deleting from the replication set.</p>
    pub fn set_region_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region_name = input;
        self
    }
    /// <p>The name of the Amazon Web Services Region you're deleting from the replication set.</p>
    pub fn get_region_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.region_name
    }
    /// Consumes the builder and constructs a [`DeleteRegionAction`](crate::types::DeleteRegionAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`region_name`](crate::types::builders::DeleteRegionActionBuilder::region_name)
    pub fn build(self) -> ::std::result::Result<crate::types::DeleteRegionAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DeleteRegionAction {
            region_name: self.region_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "region_name",
                    "region_name was not specified but it is required when building DeleteRegionAction",
                )
            })?,
        })
    }
}
