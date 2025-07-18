// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUserByPrincipalIdInput {
    /// <p>The principal ID of the user.</p>
    pub principal_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the Amazon Web Services account that the user is in. Currently, you use the ID for the Amazon Web Services account that contains your Amazon QuickSight account.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The namespace. Currently, you should set this to <code>default</code>.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
}
impl DeleteUserByPrincipalIdInput {
    /// <p>The principal ID of the user.</p>
    pub fn principal_id(&self) -> ::std::option::Option<&str> {
        self.principal_id.as_deref()
    }
    /// <p>The ID for the Amazon Web Services account that the user is in. Currently, you use the ID for the Amazon Web Services account that contains your Amazon QuickSight account.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The namespace. Currently, you should set this to <code>default</code>.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
}
impl DeleteUserByPrincipalIdInput {
    /// Creates a new builder-style object to manufacture [`DeleteUserByPrincipalIdInput`](crate::operation::delete_user_by_principal_id::DeleteUserByPrincipalIdInput).
    pub fn builder() -> crate::operation::delete_user_by_principal_id::builders::DeleteUserByPrincipalIdInputBuilder {
        crate::operation::delete_user_by_principal_id::builders::DeleteUserByPrincipalIdInputBuilder::default()
    }
}

/// A builder for [`DeleteUserByPrincipalIdInput`](crate::operation::delete_user_by_principal_id::DeleteUserByPrincipalIdInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteUserByPrincipalIdInputBuilder {
    pub(crate) principal_id: ::std::option::Option<::std::string::String>,
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
}
impl DeleteUserByPrincipalIdInputBuilder {
    /// <p>The principal ID of the user.</p>
    /// This field is required.
    pub fn principal_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The principal ID of the user.</p>
    pub fn set_principal_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_id = input;
        self
    }
    /// <p>The principal ID of the user.</p>
    pub fn get_principal_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_id
    }
    /// <p>The ID for the Amazon Web Services account that the user is in. Currently, you use the ID for the Amazon Web Services account that contains your Amazon QuickSight account.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the Amazon Web Services account that the user is in. Currently, you use the ID for the Amazon Web Services account that contains your Amazon QuickSight account.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID for the Amazon Web Services account that the user is in. Currently, you use the ID for the Amazon Web Services account that contains your Amazon QuickSight account.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The namespace. Currently, you should set this to <code>default</code>.</p>
    /// This field is required.
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace. Currently, you should set this to <code>default</code>.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace. Currently, you should set this to <code>default</code>.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// Consumes the builder and constructs a [`DeleteUserByPrincipalIdInput`](crate::operation::delete_user_by_principal_id::DeleteUserByPrincipalIdInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_user_by_principal_id::DeleteUserByPrincipalIdInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_user_by_principal_id::DeleteUserByPrincipalIdInput {
            principal_id: self.principal_id,
            aws_account_id: self.aws_account_id,
            namespace: self.namespace,
        })
    }
}
