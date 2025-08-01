// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterAccountAssociationInput {
    /// <p>The identifier of the managed thing to register with the account association.</p>
    pub managed_thing_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the account association to register with the managed thing.</p>
    pub account_association_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the device discovery job associated with this registration.</p>
    pub device_discovery_id: ::std::option::Option<::std::string::String>,
}
impl RegisterAccountAssociationInput {
    /// <p>The identifier of the managed thing to register with the account association.</p>
    pub fn managed_thing_id(&self) -> ::std::option::Option<&str> {
        self.managed_thing_id.as_deref()
    }
    /// <p>The identifier of the account association to register with the managed thing.</p>
    pub fn account_association_id(&self) -> ::std::option::Option<&str> {
        self.account_association_id.as_deref()
    }
    /// <p>The identifier of the device discovery job associated with this registration.</p>
    pub fn device_discovery_id(&self) -> ::std::option::Option<&str> {
        self.device_discovery_id.as_deref()
    }
}
impl RegisterAccountAssociationInput {
    /// Creates a new builder-style object to manufacture [`RegisterAccountAssociationInput`](crate::operation::register_account_association::RegisterAccountAssociationInput).
    pub fn builder() -> crate::operation::register_account_association::builders::RegisterAccountAssociationInputBuilder {
        crate::operation::register_account_association::builders::RegisterAccountAssociationInputBuilder::default()
    }
}

/// A builder for [`RegisterAccountAssociationInput`](crate::operation::register_account_association::RegisterAccountAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterAccountAssociationInputBuilder {
    pub(crate) managed_thing_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_association_id: ::std::option::Option<::std::string::String>,
    pub(crate) device_discovery_id: ::std::option::Option<::std::string::String>,
}
impl RegisterAccountAssociationInputBuilder {
    /// <p>The identifier of the managed thing to register with the account association.</p>
    /// This field is required.
    pub fn managed_thing_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.managed_thing_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the managed thing to register with the account association.</p>
    pub fn set_managed_thing_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.managed_thing_id = input;
        self
    }
    /// <p>The identifier of the managed thing to register with the account association.</p>
    pub fn get_managed_thing_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.managed_thing_id
    }
    /// <p>The identifier of the account association to register with the managed thing.</p>
    /// This field is required.
    pub fn account_association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the account association to register with the managed thing.</p>
    pub fn set_account_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_association_id = input;
        self
    }
    /// <p>The identifier of the account association to register with the managed thing.</p>
    pub fn get_account_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_association_id
    }
    /// <p>The identifier of the device discovery job associated with this registration.</p>
    /// This field is required.
    pub fn device_discovery_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_discovery_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the device discovery job associated with this registration.</p>
    pub fn set_device_discovery_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_discovery_id = input;
        self
    }
    /// <p>The identifier of the device discovery job associated with this registration.</p>
    pub fn get_device_discovery_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_discovery_id
    }
    /// Consumes the builder and constructs a [`RegisterAccountAssociationInput`](crate::operation::register_account_association::RegisterAccountAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::register_account_association::RegisterAccountAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::register_account_association::RegisterAccountAssociationInput {
            managed_thing_id: self.managed_thing_id,
            account_association_id: self.account_association_id,
            device_discovery_id: self.device_discovery_id,
        })
    }
}
