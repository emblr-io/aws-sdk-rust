// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAccountPoliciesInput {
    /// <p>Use this parameter to limit the returned policies to only the policies that match the policy type that you specify.</p>
    pub policy_type: ::std::option::Option<crate::types::PolicyType>,
    /// <p>Use this parameter to limit the returned policies to only the policy with the name that you specify.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
    /// <p>If you are using an account that is set up as a monitoring account for CloudWatch unified cross-account observability, you can use this to specify the account ID of a source account. If you do, the operation returns the account policy for the specified account. Currently, you can specify only one account ID in this parameter.</p>
    /// <p>If you omit this parameter, only the policy in the current account is returned.</p>
    pub account_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeAccountPoliciesInput {
    /// <p>Use this parameter to limit the returned policies to only the policies that match the policy type that you specify.</p>
    pub fn policy_type(&self) -> ::std::option::Option<&crate::types::PolicyType> {
        self.policy_type.as_ref()
    }
    /// <p>Use this parameter to limit the returned policies to only the policy with the name that you specify.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
    /// <p>If you are using an account that is set up as a monitoring account for CloudWatch unified cross-account observability, you can use this to specify the account ID of a source account. If you do, the operation returns the account policy for the specified account. Currently, you can specify only one account ID in this parameter.</p>
    /// <p>If you omit this parameter, only the policy in the current account is returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.account_identifiers.is_none()`.
    pub fn account_identifiers(&self) -> &[::std::string::String] {
        self.account_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeAccountPoliciesInput {
    /// Creates a new builder-style object to manufacture [`DescribeAccountPoliciesInput`](crate::operation::describe_account_policies::DescribeAccountPoliciesInput).
    pub fn builder() -> crate::operation::describe_account_policies::builders::DescribeAccountPoliciesInputBuilder {
        crate::operation::describe_account_policies::builders::DescribeAccountPoliciesInputBuilder::default()
    }
}

/// A builder for [`DescribeAccountPoliciesInput`](crate::operation::describe_account_policies::DescribeAccountPoliciesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAccountPoliciesInputBuilder {
    pub(crate) policy_type: ::std::option::Option<crate::types::PolicyType>,
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
    pub(crate) account_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeAccountPoliciesInputBuilder {
    /// <p>Use this parameter to limit the returned policies to only the policies that match the policy type that you specify.</p>
    /// This field is required.
    pub fn policy_type(mut self, input: crate::types::PolicyType) -> Self {
        self.policy_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this parameter to limit the returned policies to only the policies that match the policy type that you specify.</p>
    pub fn set_policy_type(mut self, input: ::std::option::Option<crate::types::PolicyType>) -> Self {
        self.policy_type = input;
        self
    }
    /// <p>Use this parameter to limit the returned policies to only the policies that match the policy type that you specify.</p>
    pub fn get_policy_type(&self) -> &::std::option::Option<crate::types::PolicyType> {
        &self.policy_type
    }
    /// <p>Use this parameter to limit the returned policies to only the policy with the name that you specify.</p>
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Use this parameter to limit the returned policies to only the policy with the name that you specify.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>Use this parameter to limit the returned policies to only the policy with the name that you specify.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    /// Appends an item to `account_identifiers`.
    ///
    /// To override the contents of this collection use [`set_account_identifiers`](Self::set_account_identifiers).
    ///
    /// <p>If you are using an account that is set up as a monitoring account for CloudWatch unified cross-account observability, you can use this to specify the account ID of a source account. If you do, the operation returns the account policy for the specified account. Currently, you can specify only one account ID in this parameter.</p>
    /// <p>If you omit this parameter, only the policy in the current account is returned.</p>
    pub fn account_identifiers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.account_identifiers.unwrap_or_default();
        v.push(input.into());
        self.account_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>If you are using an account that is set up as a monitoring account for CloudWatch unified cross-account observability, you can use this to specify the account ID of a source account. If you do, the operation returns the account policy for the specified account. Currently, you can specify only one account ID in this parameter.</p>
    /// <p>If you omit this parameter, only the policy in the current account is returned.</p>
    pub fn set_account_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.account_identifiers = input;
        self
    }
    /// <p>If you are using an account that is set up as a monitoring account for CloudWatch unified cross-account observability, you can use this to specify the account ID of a source account. If you do, the operation returns the account policy for the specified account. Currently, you can specify only one account ID in this parameter.</p>
    /// <p>If you omit this parameter, only the policy in the current account is returned.</p>
    pub fn get_account_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.account_identifiers
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of items to return. (You received this token from a previous call.)</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeAccountPoliciesInput`](crate::operation::describe_account_policies::DescribeAccountPoliciesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_account_policies::DescribeAccountPoliciesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_account_policies::DescribeAccountPoliciesInput {
            policy_type: self.policy_type,
            policy_name: self.policy_name,
            account_identifiers: self.account_identifiers,
            next_token: self.next_token,
        })
    }
}
