// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the action to remove a witness Region from a MRSC global table. You cannot delete a single witness from a MRSC global table - you must delete both a replica and the witness together. The deletion of both a witness and replica converts the remaining replica to a single-Region DynamoDB table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteGlobalTableWitnessGroupMemberAction {
    /// <p>The witness Region name to be removed from the MRSC global table.</p>
    pub region_name: ::std::string::String,
}
impl DeleteGlobalTableWitnessGroupMemberAction {
    /// <p>The witness Region name to be removed from the MRSC global table.</p>
    pub fn region_name(&self) -> &str {
        use std::ops::Deref;
        self.region_name.deref()
    }
}
impl DeleteGlobalTableWitnessGroupMemberAction {
    /// Creates a new builder-style object to manufacture [`DeleteGlobalTableWitnessGroupMemberAction`](crate::types::DeleteGlobalTableWitnessGroupMemberAction).
    pub fn builder() -> crate::types::builders::DeleteGlobalTableWitnessGroupMemberActionBuilder {
        crate::types::builders::DeleteGlobalTableWitnessGroupMemberActionBuilder::default()
    }
}

/// A builder for [`DeleteGlobalTableWitnessGroupMemberAction`](crate::types::DeleteGlobalTableWitnessGroupMemberAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteGlobalTableWitnessGroupMemberActionBuilder {
    pub(crate) region_name: ::std::option::Option<::std::string::String>,
}
impl DeleteGlobalTableWitnessGroupMemberActionBuilder {
    /// <p>The witness Region name to be removed from the MRSC global table.</p>
    /// This field is required.
    pub fn region_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The witness Region name to be removed from the MRSC global table.</p>
    pub fn set_region_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region_name = input;
        self
    }
    /// <p>The witness Region name to be removed from the MRSC global table.</p>
    pub fn get_region_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.region_name
    }
    /// Consumes the builder and constructs a [`DeleteGlobalTableWitnessGroupMemberAction`](crate::types::DeleteGlobalTableWitnessGroupMemberAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`region_name`](crate::types::builders::DeleteGlobalTableWitnessGroupMemberActionBuilder::region_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::DeleteGlobalTableWitnessGroupMemberAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DeleteGlobalTableWitnessGroupMemberAction {
            region_name: self.region_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "region_name",
                    "region_name was not specified but it is required when building DeleteGlobalTableWitnessGroupMemberAction",
                )
            })?,
        })
    }
}
