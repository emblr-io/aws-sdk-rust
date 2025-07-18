// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociatePermissionInput {
    /// <p>The unique identifier of the Amazon Q Business application.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The statement ID of the permission to remove.</p>
    pub statement_id: ::std::option::Option<::std::string::String>,
}
impl DisassociatePermissionInput {
    /// <p>The unique identifier of the Amazon Q Business application.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The statement ID of the permission to remove.</p>
    pub fn statement_id(&self) -> ::std::option::Option<&str> {
        self.statement_id.as_deref()
    }
}
impl DisassociatePermissionInput {
    /// Creates a new builder-style object to manufacture [`DisassociatePermissionInput`](crate::operation::disassociate_permission::DisassociatePermissionInput).
    pub fn builder() -> crate::operation::disassociate_permission::builders::DisassociatePermissionInputBuilder {
        crate::operation::disassociate_permission::builders::DisassociatePermissionInputBuilder::default()
    }
}

/// A builder for [`DisassociatePermissionInput`](crate::operation::disassociate_permission::DisassociatePermissionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociatePermissionInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) statement_id: ::std::option::Option<::std::string::String>,
}
impl DisassociatePermissionInputBuilder {
    /// <p>The unique identifier of the Amazon Q Business application.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the Amazon Q Business application.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The unique identifier of the Amazon Q Business application.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The statement ID of the permission to remove.</p>
    /// This field is required.
    pub fn statement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.statement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The statement ID of the permission to remove.</p>
    pub fn set_statement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.statement_id = input;
        self
    }
    /// <p>The statement ID of the permission to remove.</p>
    pub fn get_statement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.statement_id
    }
    /// Consumes the builder and constructs a [`DisassociatePermissionInput`](crate::operation::disassociate_permission::DisassociatePermissionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::disassociate_permission::DisassociatePermissionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::disassociate_permission::DisassociatePermissionInput {
            application_id: self.application_id,
            statement_id: self.statement_id,
        })
    }
}
