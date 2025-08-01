// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateAttributeGroupInput {
    /// <p>The name, ID, or ARN of the application.</p>
    pub application: ::std::option::Option<::std::string::String>,
    /// <p>The name, ID, or ARN of the attribute group that holds the attributes to describe the application.</p>
    pub attribute_group: ::std::option::Option<::std::string::String>,
}
impl DisassociateAttributeGroupInput {
    /// <p>The name, ID, or ARN of the application.</p>
    pub fn application(&self) -> ::std::option::Option<&str> {
        self.application.as_deref()
    }
    /// <p>The name, ID, or ARN of the attribute group that holds the attributes to describe the application.</p>
    pub fn attribute_group(&self) -> ::std::option::Option<&str> {
        self.attribute_group.as_deref()
    }
}
impl DisassociateAttributeGroupInput {
    /// Creates a new builder-style object to manufacture [`DisassociateAttributeGroupInput`](crate::operation::disassociate_attribute_group::DisassociateAttributeGroupInput).
    pub fn builder() -> crate::operation::disassociate_attribute_group::builders::DisassociateAttributeGroupInputBuilder {
        crate::operation::disassociate_attribute_group::builders::DisassociateAttributeGroupInputBuilder::default()
    }
}

/// A builder for [`DisassociateAttributeGroupInput`](crate::operation::disassociate_attribute_group::DisassociateAttributeGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateAttributeGroupInputBuilder {
    pub(crate) application: ::std::option::Option<::std::string::String>,
    pub(crate) attribute_group: ::std::option::Option<::std::string::String>,
}
impl DisassociateAttributeGroupInputBuilder {
    /// <p>The name, ID, or ARN of the application.</p>
    /// This field is required.
    pub fn application(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name, ID, or ARN of the application.</p>
    pub fn set_application(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application = input;
        self
    }
    /// <p>The name, ID, or ARN of the application.</p>
    pub fn get_application(&self) -> &::std::option::Option<::std::string::String> {
        &self.application
    }
    /// <p>The name, ID, or ARN of the attribute group that holds the attributes to describe the application.</p>
    /// This field is required.
    pub fn attribute_group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attribute_group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name, ID, or ARN of the attribute group that holds the attributes to describe the application.</p>
    pub fn set_attribute_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attribute_group = input;
        self
    }
    /// <p>The name, ID, or ARN of the attribute group that holds the attributes to describe the application.</p>
    pub fn get_attribute_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.attribute_group
    }
    /// Consumes the builder and constructs a [`DisassociateAttributeGroupInput`](crate::operation::disassociate_attribute_group::DisassociateAttributeGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_attribute_group::DisassociateAttributeGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::disassociate_attribute_group::DisassociateAttributeGroupInput {
            application: self.application,
            attribute_group: self.attribute_group,
        })
    }
}
