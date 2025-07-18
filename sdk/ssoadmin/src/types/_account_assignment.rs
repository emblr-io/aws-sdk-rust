// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The assignment that indicates a principal's limited access to a specified Amazon Web Services account with a specified permission set.</p><note>
/// <p>The term <i>principal</i> here refers to a user or group that is defined in IAM Identity Center.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccountAssignment {
    /// <p>The identifier of the Amazon Web Services account.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the permission set. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub permission_set_arn: ::std::option::Option<::std::string::String>,
    /// <p>The entity type for which the assignment will be created.</p>
    pub principal_type: ::std::option::Option<crate::types::PrincipalType>,
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    pub principal_id: ::std::option::Option<::std::string::String>,
}
impl AccountAssignment {
    /// <p>The identifier of the Amazon Web Services account.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The ARN of the permission set. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn permission_set_arn(&self) -> ::std::option::Option<&str> {
        self.permission_set_arn.as_deref()
    }
    /// <p>The entity type for which the assignment will be created.</p>
    pub fn principal_type(&self) -> ::std::option::Option<&crate::types::PrincipalType> {
        self.principal_type.as_ref()
    }
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    pub fn principal_id(&self) -> ::std::option::Option<&str> {
        self.principal_id.as_deref()
    }
}
impl AccountAssignment {
    /// Creates a new builder-style object to manufacture [`AccountAssignment`](crate::types::AccountAssignment).
    pub fn builder() -> crate::types::builders::AccountAssignmentBuilder {
        crate::types::builders::AccountAssignmentBuilder::default()
    }
}

/// A builder for [`AccountAssignment`](crate::types::AccountAssignment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccountAssignmentBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) permission_set_arn: ::std::option::Option<::std::string::String>,
    pub(crate) principal_type: ::std::option::Option<crate::types::PrincipalType>,
    pub(crate) principal_id: ::std::option::Option<::std::string::String>,
}
impl AccountAssignmentBuilder {
    /// <p>The identifier of the Amazon Web Services account.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Web Services account.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The identifier of the Amazon Web Services account.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The ARN of the permission set. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn permission_set_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.permission_set_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the permission set. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_permission_set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.permission_set_arn = input;
        self
    }
    /// <p>The ARN of the permission set. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_permission_set_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.permission_set_arn
    }
    /// <p>The entity type for which the assignment will be created.</p>
    pub fn principal_type(mut self, input: crate::types::PrincipalType) -> Self {
        self.principal_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The entity type for which the assignment will be created.</p>
    pub fn set_principal_type(mut self, input: ::std::option::Option<crate::types::PrincipalType>) -> Self {
        self.principal_type = input;
        self
    }
    /// <p>The entity type for which the assignment will be created.</p>
    pub fn get_principal_type(&self) -> &::std::option::Option<crate::types::PrincipalType> {
        &self.principal_type
    }
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    pub fn principal_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    pub fn set_principal_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_id = input;
        self
    }
    /// <p>An identifier for an object in IAM Identity Center, such as a user or group. PrincipalIds are GUIDs (For example, f81d4fae-7dec-11d0-a765-00a0c91e6bf6). For more information about PrincipalIds in IAM Identity Center, see the <a href="/singlesignon/latest/IdentityStoreAPIReference/welcome.html">IAM Identity Center Identity Store API Reference</a>.</p>
    pub fn get_principal_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_id
    }
    /// Consumes the builder and constructs a [`AccountAssignment`](crate::types::AccountAssignment).
    pub fn build(self) -> crate::types::AccountAssignment {
        crate::types::AccountAssignment {
            account_id: self.account_id,
            permission_set_arn: self.permission_set_arn,
            principal_type: self.principal_type,
            principal_id: self.principal_id,
        }
    }
}
