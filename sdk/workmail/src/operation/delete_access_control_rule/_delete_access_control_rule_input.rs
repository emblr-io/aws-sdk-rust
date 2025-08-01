// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAccessControlRuleInput {
    /// <p>The identifier for the organization.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the access control rule.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeleteAccessControlRuleInput {
    /// <p>The identifier for the organization.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The name of the access control rule.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DeleteAccessControlRuleInput {
    /// Creates a new builder-style object to manufacture [`DeleteAccessControlRuleInput`](crate::operation::delete_access_control_rule::DeleteAccessControlRuleInput).
    pub fn builder() -> crate::operation::delete_access_control_rule::builders::DeleteAccessControlRuleInputBuilder {
        crate::operation::delete_access_control_rule::builders::DeleteAccessControlRuleInputBuilder::default()
    }
}

/// A builder for [`DeleteAccessControlRuleInput`](crate::operation::delete_access_control_rule::DeleteAccessControlRuleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAccessControlRuleInputBuilder {
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeleteAccessControlRuleInputBuilder {
    /// <p>The identifier for the organization.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the organization.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The identifier for the organization.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The name of the access control rule.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the access control rule.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the access control rule.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeleteAccessControlRuleInput`](crate::operation::delete_access_control_rule::DeleteAccessControlRuleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_access_control_rule::DeleteAccessControlRuleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_access_control_rule::DeleteAccessControlRuleInput {
            organization_id: self.organization_id,
            name: self.name,
        })
    }
}
