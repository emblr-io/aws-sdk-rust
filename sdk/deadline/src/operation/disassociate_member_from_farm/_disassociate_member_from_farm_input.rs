// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateMemberFromFarmInput {
    /// <p>The farm ID of the farm to disassociate from the member.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>A member's principal ID to disassociate from a farm.</p>
    pub principal_id: ::std::option::Option<::std::string::String>,
}
impl DisassociateMemberFromFarmInput {
    /// <p>The farm ID of the farm to disassociate from the member.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>A member's principal ID to disassociate from a farm.</p>
    pub fn principal_id(&self) -> ::std::option::Option<&str> {
        self.principal_id.as_deref()
    }
}
impl DisassociateMemberFromFarmInput {
    /// Creates a new builder-style object to manufacture [`DisassociateMemberFromFarmInput`](crate::operation::disassociate_member_from_farm::DisassociateMemberFromFarmInput).
    pub fn builder() -> crate::operation::disassociate_member_from_farm::builders::DisassociateMemberFromFarmInputBuilder {
        crate::operation::disassociate_member_from_farm::builders::DisassociateMemberFromFarmInputBuilder::default()
    }
}

/// A builder for [`DisassociateMemberFromFarmInput`](crate::operation::disassociate_member_from_farm::DisassociateMemberFromFarmInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateMemberFromFarmInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) principal_id: ::std::option::Option<::std::string::String>,
}
impl DisassociateMemberFromFarmInputBuilder {
    /// <p>The farm ID of the farm to disassociate from the member.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The farm ID of the farm to disassociate from the member.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The farm ID of the farm to disassociate from the member.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>A member's principal ID to disassociate from a farm.</p>
    /// This field is required.
    pub fn principal_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A member's principal ID to disassociate from a farm.</p>
    pub fn set_principal_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_id = input;
        self
    }
    /// <p>A member's principal ID to disassociate from a farm.</p>
    pub fn get_principal_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_id
    }
    /// Consumes the builder and constructs a [`DisassociateMemberFromFarmInput`](crate::operation::disassociate_member_from_farm::DisassociateMemberFromFarmInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_member_from_farm::DisassociateMemberFromFarmInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::disassociate_member_from_farm::DisassociateMemberFromFarmInput {
            farm_id: self.farm_id,
            principal_id: self.principal_id,
        })
    }
}
