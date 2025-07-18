// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSecurityControlDefinitionInput {
    /// <p>The ID of the security control to retrieve the definition for. This field doesn’t accept an Amazon Resource Name (ARN).</p>
    pub security_control_id: ::std::option::Option<::std::string::String>,
}
impl GetSecurityControlDefinitionInput {
    /// <p>The ID of the security control to retrieve the definition for. This field doesn’t accept an Amazon Resource Name (ARN).</p>
    pub fn security_control_id(&self) -> ::std::option::Option<&str> {
        self.security_control_id.as_deref()
    }
}
impl GetSecurityControlDefinitionInput {
    /// Creates a new builder-style object to manufacture [`GetSecurityControlDefinitionInput`](crate::operation::get_security_control_definition::GetSecurityControlDefinitionInput).
    pub fn builder() -> crate::operation::get_security_control_definition::builders::GetSecurityControlDefinitionInputBuilder {
        crate::operation::get_security_control_definition::builders::GetSecurityControlDefinitionInputBuilder::default()
    }
}

/// A builder for [`GetSecurityControlDefinitionInput`](crate::operation::get_security_control_definition::GetSecurityControlDefinitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSecurityControlDefinitionInputBuilder {
    pub(crate) security_control_id: ::std::option::Option<::std::string::String>,
}
impl GetSecurityControlDefinitionInputBuilder {
    /// <p>The ID of the security control to retrieve the definition for. This field doesn’t accept an Amazon Resource Name (ARN).</p>
    /// This field is required.
    pub fn security_control_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.security_control_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the security control to retrieve the definition for. This field doesn’t accept an Amazon Resource Name (ARN).</p>
    pub fn set_security_control_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.security_control_id = input;
        self
    }
    /// <p>The ID of the security control to retrieve the definition for. This field doesn’t accept an Amazon Resource Name (ARN).</p>
    pub fn get_security_control_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.security_control_id
    }
    /// Consumes the builder and constructs a [`GetSecurityControlDefinitionInput`](crate::operation::get_security_control_definition::GetSecurityControlDefinitionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_security_control_definition::GetSecurityControlDefinitionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_security_control_definition::GetSecurityControlDefinitionInput {
            security_control_id: self.security_control_id,
        })
    }
}
