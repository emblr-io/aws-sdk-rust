// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The permission granted to the Amazon Q App.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PermissionOutput {
    /// <p>The action associated with the permission.</p>
    pub action: crate::types::Action,
    /// <p>The principal user to which the permission applies.</p>
    pub principal: ::std::option::Option<crate::types::PrincipalOutput>,
}
impl PermissionOutput {
    /// <p>The action associated with the permission.</p>
    pub fn action(&self) -> &crate::types::Action {
        &self.action
    }
    /// <p>The principal user to which the permission applies.</p>
    pub fn principal(&self) -> ::std::option::Option<&crate::types::PrincipalOutput> {
        self.principal.as_ref()
    }
}
impl PermissionOutput {
    /// Creates a new builder-style object to manufacture [`PermissionOutput`](crate::types::PermissionOutput).
    pub fn builder() -> crate::types::builders::PermissionOutputBuilder {
        crate::types::builders::PermissionOutputBuilder::default()
    }
}

/// A builder for [`PermissionOutput`](crate::types::PermissionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PermissionOutputBuilder {
    pub(crate) action: ::std::option::Option<crate::types::Action>,
    pub(crate) principal: ::std::option::Option<crate::types::PrincipalOutput>,
}
impl PermissionOutputBuilder {
    /// <p>The action associated with the permission.</p>
    /// This field is required.
    pub fn action(mut self, input: crate::types::Action) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action associated with the permission.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::Action>) -> Self {
        self.action = input;
        self
    }
    /// <p>The action associated with the permission.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::Action> {
        &self.action
    }
    /// <p>The principal user to which the permission applies.</p>
    /// This field is required.
    pub fn principal(mut self, input: crate::types::PrincipalOutput) -> Self {
        self.principal = ::std::option::Option::Some(input);
        self
    }
    /// <p>The principal user to which the permission applies.</p>
    pub fn set_principal(mut self, input: ::std::option::Option<crate::types::PrincipalOutput>) -> Self {
        self.principal = input;
        self
    }
    /// <p>The principal user to which the permission applies.</p>
    pub fn get_principal(&self) -> &::std::option::Option<crate::types::PrincipalOutput> {
        &self.principal
    }
    /// Consumes the builder and constructs a [`PermissionOutput`](crate::types::PermissionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`action`](crate::types::builders::PermissionOutputBuilder::action)
    pub fn build(self) -> ::std::result::Result<crate::types::PermissionOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PermissionOutput {
            action: self.action.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "action",
                    "action was not specified but it is required when building PermissionOutput",
                )
            })?,
            principal: self.principal,
        })
    }
}
