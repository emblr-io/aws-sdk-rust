// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a grant.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Grant {
    /// <p>The grantee.</p>
    pub grantee: ::std::option::Option<crate::types::Grantee>,
    /// <p>Specifies the permission given to the grantee.</p>
    pub permission: ::std::option::Option<crate::types::Permission>,
}
impl Grant {
    /// <p>The grantee.</p>
    pub fn grantee(&self) -> ::std::option::Option<&crate::types::Grantee> {
        self.grantee.as_ref()
    }
    /// <p>Specifies the permission given to the grantee.</p>
    pub fn permission(&self) -> ::std::option::Option<&crate::types::Permission> {
        self.permission.as_ref()
    }
}
impl Grant {
    /// Creates a new builder-style object to manufacture [`Grant`](crate::types::Grant).
    pub fn builder() -> crate::types::builders::GrantBuilder {
        crate::types::builders::GrantBuilder::default()
    }
}

/// A builder for [`Grant`](crate::types::Grant).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GrantBuilder {
    pub(crate) grantee: ::std::option::Option<crate::types::Grantee>,
    pub(crate) permission: ::std::option::Option<crate::types::Permission>,
}
impl GrantBuilder {
    /// <p>The grantee.</p>
    pub fn grantee(mut self, input: crate::types::Grantee) -> Self {
        self.grantee = ::std::option::Option::Some(input);
        self
    }
    /// <p>The grantee.</p>
    pub fn set_grantee(mut self, input: ::std::option::Option<crate::types::Grantee>) -> Self {
        self.grantee = input;
        self
    }
    /// <p>The grantee.</p>
    pub fn get_grantee(&self) -> &::std::option::Option<crate::types::Grantee> {
        &self.grantee
    }
    /// <p>Specifies the permission given to the grantee.</p>
    pub fn permission(mut self, input: crate::types::Permission) -> Self {
        self.permission = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the permission given to the grantee.</p>
    pub fn set_permission(mut self, input: ::std::option::Option<crate::types::Permission>) -> Self {
        self.permission = input;
        self
    }
    /// <p>Specifies the permission given to the grantee.</p>
    pub fn get_permission(&self) -> &::std::option::Option<crate::types::Permission> {
        &self.permission
    }
    /// Consumes the builder and constructs a [`Grant`](crate::types::Grant).
    pub fn build(self) -> crate::types::Grant {
        crate::types::Grant {
            grantee: self.grantee,
            permission: self.permission,
        }
    }
}
