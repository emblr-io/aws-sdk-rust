// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCustomerManagedPolicyReferencesInPermissionSetInput {
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed.</p>
    pub instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the <code>PermissionSet</code>.</p>
    pub permission_set_arn: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to display for the list call.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token for the list API. Initially the value is null. Use the output of previous API calls to make subsequent calls.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListCustomerManagedPolicyReferencesInPermissionSetInput {
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed.</p>
    pub fn instance_arn(&self) -> ::std::option::Option<&str> {
        self.instance_arn.as_deref()
    }
    /// <p>The ARN of the <code>PermissionSet</code>.</p>
    pub fn permission_set_arn(&self) -> ::std::option::Option<&str> {
        self.permission_set_arn.as_deref()
    }
    /// <p>The maximum number of results to display for the list call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token for the list API. Initially the value is null. Use the output of previous API calls to make subsequent calls.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListCustomerManagedPolicyReferencesInPermissionSetInput {
    /// Creates a new builder-style object to manufacture [`ListCustomerManagedPolicyReferencesInPermissionSetInput`](crate::operation::list_customer_managed_policy_references_in_permission_set::ListCustomerManagedPolicyReferencesInPermissionSetInput).
    pub fn builder() -> crate::operation::list_customer_managed_policy_references_in_permission_set::builders::ListCustomerManagedPolicyReferencesInPermissionSetInputBuilder{
        crate::operation::list_customer_managed_policy_references_in_permission_set::builders::ListCustomerManagedPolicyReferencesInPermissionSetInputBuilder::default()
    }
}

/// A builder for [`ListCustomerManagedPolicyReferencesInPermissionSetInput`](crate::operation::list_customer_managed_policy_references_in_permission_set::ListCustomerManagedPolicyReferencesInPermissionSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCustomerManagedPolicyReferencesInPermissionSetInputBuilder {
    pub(crate) instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) permission_set_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListCustomerManagedPolicyReferencesInPermissionSetInputBuilder {
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed.</p>
    /// This field is required.
    pub fn instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed.</p>
    pub fn set_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_arn = input;
        self
    }
    /// <p>The ARN of the IAM Identity Center instance under which the operation will be executed.</p>
    pub fn get_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_arn
    }
    /// <p>The ARN of the <code>PermissionSet</code>.</p>
    /// This field is required.
    pub fn permission_set_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.permission_set_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the <code>PermissionSet</code>.</p>
    pub fn set_permission_set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.permission_set_arn = input;
        self
    }
    /// <p>The ARN of the <code>PermissionSet</code>.</p>
    pub fn get_permission_set_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.permission_set_arn
    }
    /// <p>The maximum number of results to display for the list call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to display for the list call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to display for the list call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token for the list API. Initially the value is null. Use the output of previous API calls to make subsequent calls.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token for the list API. Initially the value is null. Use the output of previous API calls to make subsequent calls.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token for the list API. Initially the value is null. Use the output of previous API calls to make subsequent calls.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListCustomerManagedPolicyReferencesInPermissionSetInput`](crate::operation::list_customer_managed_policy_references_in_permission_set::ListCustomerManagedPolicyReferencesInPermissionSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_customer_managed_policy_references_in_permission_set::ListCustomerManagedPolicyReferencesInPermissionSetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_customer_managed_policy_references_in_permission_set::ListCustomerManagedPolicyReferencesInPermissionSetInput {
                instance_arn: self.instance_arn,
                permission_set_arn: self.permission_set_arn,
                max_results: self.max_results,
                next_token: self.next_token,
            },
        )
    }
}
