// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateApplicationFromEntitlementInput {
    /// <p>The name of the stack with which the entitlement is associated.</p>
    pub stack_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the entitlement.</p>
    pub entitlement_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the application to remove from the entitlement.</p>
    pub application_identifier: ::std::option::Option<::std::string::String>,
}
impl DisassociateApplicationFromEntitlementInput {
    /// <p>The name of the stack with which the entitlement is associated.</p>
    pub fn stack_name(&self) -> ::std::option::Option<&str> {
        self.stack_name.as_deref()
    }
    /// <p>The name of the entitlement.</p>
    pub fn entitlement_name(&self) -> ::std::option::Option<&str> {
        self.entitlement_name.as_deref()
    }
    /// <p>The identifier of the application to remove from the entitlement.</p>
    pub fn application_identifier(&self) -> ::std::option::Option<&str> {
        self.application_identifier.as_deref()
    }
}
impl DisassociateApplicationFromEntitlementInput {
    /// Creates a new builder-style object to manufacture [`DisassociateApplicationFromEntitlementInput`](crate::operation::disassociate_application_from_entitlement::DisassociateApplicationFromEntitlementInput).
    pub fn builder() -> crate::operation::disassociate_application_from_entitlement::builders::DisassociateApplicationFromEntitlementInputBuilder {
        crate::operation::disassociate_application_from_entitlement::builders::DisassociateApplicationFromEntitlementInputBuilder::default()
    }
}

/// A builder for [`DisassociateApplicationFromEntitlementInput`](crate::operation::disassociate_application_from_entitlement::DisassociateApplicationFromEntitlementInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateApplicationFromEntitlementInputBuilder {
    pub(crate) stack_name: ::std::option::Option<::std::string::String>,
    pub(crate) entitlement_name: ::std::option::Option<::std::string::String>,
    pub(crate) application_identifier: ::std::option::Option<::std::string::String>,
}
impl DisassociateApplicationFromEntitlementInputBuilder {
    /// <p>The name of the stack with which the entitlement is associated.</p>
    /// This field is required.
    pub fn stack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stack with which the entitlement is associated.</p>
    pub fn set_stack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_name = input;
        self
    }
    /// <p>The name of the stack with which the entitlement is associated.</p>
    pub fn get_stack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_name
    }
    /// <p>The name of the entitlement.</p>
    /// This field is required.
    pub fn entitlement_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entitlement_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the entitlement.</p>
    pub fn set_entitlement_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entitlement_name = input;
        self
    }
    /// <p>The name of the entitlement.</p>
    pub fn get_entitlement_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.entitlement_name
    }
    /// <p>The identifier of the application to remove from the entitlement.</p>
    /// This field is required.
    pub fn application_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the application to remove from the entitlement.</p>
    pub fn set_application_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_identifier = input;
        self
    }
    /// <p>The identifier of the application to remove from the entitlement.</p>
    pub fn get_application_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_identifier
    }
    /// Consumes the builder and constructs a [`DisassociateApplicationFromEntitlementInput`](crate::operation::disassociate_application_from_entitlement::DisassociateApplicationFromEntitlementInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_application_from_entitlement::DisassociateApplicationFromEntitlementInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::disassociate_application_from_entitlement::DisassociateApplicationFromEntitlementInput {
                stack_name: self.stack_name,
                entitlement_name: self.entitlement_name,
                application_identifier: self.application_identifier,
            },
        )
    }
}
