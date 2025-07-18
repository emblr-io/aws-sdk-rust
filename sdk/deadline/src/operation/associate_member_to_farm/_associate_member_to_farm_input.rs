// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateMemberToFarmInput {
    /// <p>The ID of the farm to associate with the member.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>The member's principal ID to associate with the farm.</p>
    pub principal_id: ::std::option::Option<::std::string::String>,
    /// <p>The principal type of the member to associate with the farm.</p>
    pub principal_type: ::std::option::Option<crate::types::DeadlinePrincipalType>,
    /// <p>The identity store ID of the member to associate with the farm.</p>
    pub identity_store_id: ::std::option::Option<::std::string::String>,
    /// <p>The principal's membership level for the associated farm.</p>
    pub membership_level: ::std::option::Option<crate::types::MembershipLevel>,
}
impl AssociateMemberToFarmInput {
    /// <p>The ID of the farm to associate with the member.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>The member's principal ID to associate with the farm.</p>
    pub fn principal_id(&self) -> ::std::option::Option<&str> {
        self.principal_id.as_deref()
    }
    /// <p>The principal type of the member to associate with the farm.</p>
    pub fn principal_type(&self) -> ::std::option::Option<&crate::types::DeadlinePrincipalType> {
        self.principal_type.as_ref()
    }
    /// <p>The identity store ID of the member to associate with the farm.</p>
    pub fn identity_store_id(&self) -> ::std::option::Option<&str> {
        self.identity_store_id.as_deref()
    }
    /// <p>The principal's membership level for the associated farm.</p>
    pub fn membership_level(&self) -> ::std::option::Option<&crate::types::MembershipLevel> {
        self.membership_level.as_ref()
    }
}
impl AssociateMemberToFarmInput {
    /// Creates a new builder-style object to manufacture [`AssociateMemberToFarmInput`](crate::operation::associate_member_to_farm::AssociateMemberToFarmInput).
    pub fn builder() -> crate::operation::associate_member_to_farm::builders::AssociateMemberToFarmInputBuilder {
        crate::operation::associate_member_to_farm::builders::AssociateMemberToFarmInputBuilder::default()
    }
}

/// A builder for [`AssociateMemberToFarmInput`](crate::operation::associate_member_to_farm::AssociateMemberToFarmInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateMemberToFarmInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) principal_id: ::std::option::Option<::std::string::String>,
    pub(crate) principal_type: ::std::option::Option<crate::types::DeadlinePrincipalType>,
    pub(crate) identity_store_id: ::std::option::Option<::std::string::String>,
    pub(crate) membership_level: ::std::option::Option<crate::types::MembershipLevel>,
}
impl AssociateMemberToFarmInputBuilder {
    /// <p>The ID of the farm to associate with the member.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the farm to associate with the member.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The ID of the farm to associate with the member.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The member's principal ID to associate with the farm.</p>
    /// This field is required.
    pub fn principal_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The member's principal ID to associate with the farm.</p>
    pub fn set_principal_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_id = input;
        self
    }
    /// <p>The member's principal ID to associate with the farm.</p>
    pub fn get_principal_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_id
    }
    /// <p>The principal type of the member to associate with the farm.</p>
    /// This field is required.
    pub fn principal_type(mut self, input: crate::types::DeadlinePrincipalType) -> Self {
        self.principal_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The principal type of the member to associate with the farm.</p>
    pub fn set_principal_type(mut self, input: ::std::option::Option<crate::types::DeadlinePrincipalType>) -> Self {
        self.principal_type = input;
        self
    }
    /// <p>The principal type of the member to associate with the farm.</p>
    pub fn get_principal_type(&self) -> &::std::option::Option<crate::types::DeadlinePrincipalType> {
        &self.principal_type
    }
    /// <p>The identity store ID of the member to associate with the farm.</p>
    /// This field is required.
    pub fn identity_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identity store ID of the member to associate with the farm.</p>
    pub fn set_identity_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_store_id = input;
        self
    }
    /// <p>The identity store ID of the member to associate with the farm.</p>
    pub fn get_identity_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_store_id
    }
    /// <p>The principal's membership level for the associated farm.</p>
    /// This field is required.
    pub fn membership_level(mut self, input: crate::types::MembershipLevel) -> Self {
        self.membership_level = ::std::option::Option::Some(input);
        self
    }
    /// <p>The principal's membership level for the associated farm.</p>
    pub fn set_membership_level(mut self, input: ::std::option::Option<crate::types::MembershipLevel>) -> Self {
        self.membership_level = input;
        self
    }
    /// <p>The principal's membership level for the associated farm.</p>
    pub fn get_membership_level(&self) -> &::std::option::Option<crate::types::MembershipLevel> {
        &self.membership_level
    }
    /// Consumes the builder and constructs a [`AssociateMemberToFarmInput`](crate::operation::associate_member_to_farm::AssociateMemberToFarmInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::associate_member_to_farm::AssociateMemberToFarmInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::associate_member_to_farm::AssociateMemberToFarmInput {
            farm_id: self.farm_id,
            principal_id: self.principal_id,
            principal_type: self.principal_type,
            identity_store_id: self.identity_store_id,
            membership_level: self.membership_level,
        })
    }
}
