// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateUserProficienciesInput {
    /// <p>The identifier of the Amazon Connect instance. You can find the instance ID in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the user account.</p>
    pub user_id: ::std::option::Option<::std::string::String>,
    /// <p>The proficiencies to disassociate from the user.</p>
    pub user_proficiencies: ::std::option::Option<::std::vec::Vec<crate::types::UserProficiencyDisassociate>>,
}
impl DisassociateUserProficienciesInput {
    /// <p>The identifier of the Amazon Connect instance. You can find the instance ID in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The identifier of the user account.</p>
    pub fn user_id(&self) -> ::std::option::Option<&str> {
        self.user_id.as_deref()
    }
    /// <p>The proficiencies to disassociate from the user.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_proficiencies.is_none()`.
    pub fn user_proficiencies(&self) -> &[crate::types::UserProficiencyDisassociate] {
        self.user_proficiencies.as_deref().unwrap_or_default()
    }
}
impl DisassociateUserProficienciesInput {
    /// Creates a new builder-style object to manufacture [`DisassociateUserProficienciesInput`](crate::operation::disassociate_user_proficiencies::DisassociateUserProficienciesInput).
    pub fn builder() -> crate::operation::disassociate_user_proficiencies::builders::DisassociateUserProficienciesInputBuilder {
        crate::operation::disassociate_user_proficiencies::builders::DisassociateUserProficienciesInputBuilder::default()
    }
}

/// A builder for [`DisassociateUserProficienciesInput`](crate::operation::disassociate_user_proficiencies::DisassociateUserProficienciesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateUserProficienciesInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_proficiencies: ::std::option::Option<::std::vec::Vec<crate::types::UserProficiencyDisassociate>>,
}
impl DisassociateUserProficienciesInputBuilder {
    /// <p>The identifier of the Amazon Connect instance. You can find the instance ID in the Amazon Resource Name (ARN) of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can find the instance ID in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can find the instance ID in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The identifier of the user account.</p>
    /// This field is required.
    pub fn user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the user account.</p>
    pub fn set_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_id = input;
        self
    }
    /// <p>The identifier of the user account.</p>
    pub fn get_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_id
    }
    /// Appends an item to `user_proficiencies`.
    ///
    /// To override the contents of this collection use [`set_user_proficiencies`](Self::set_user_proficiencies).
    ///
    /// <p>The proficiencies to disassociate from the user.</p>
    pub fn user_proficiencies(mut self, input: crate::types::UserProficiencyDisassociate) -> Self {
        let mut v = self.user_proficiencies.unwrap_or_default();
        v.push(input);
        self.user_proficiencies = ::std::option::Option::Some(v);
        self
    }
    /// <p>The proficiencies to disassociate from the user.</p>
    pub fn set_user_proficiencies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UserProficiencyDisassociate>>) -> Self {
        self.user_proficiencies = input;
        self
    }
    /// <p>The proficiencies to disassociate from the user.</p>
    pub fn get_user_proficiencies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UserProficiencyDisassociate>> {
        &self.user_proficiencies
    }
    /// Consumes the builder and constructs a [`DisassociateUserProficienciesInput`](crate::operation::disassociate_user_proficiencies::DisassociateUserProficienciesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_user_proficiencies::DisassociateUserProficienciesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::disassociate_user_proficiencies::DisassociateUserProficienciesInput {
            instance_id: self.instance_id,
            user_id: self.user_id,
            user_proficiencies: self.user_proficiencies,
        })
    }
}
