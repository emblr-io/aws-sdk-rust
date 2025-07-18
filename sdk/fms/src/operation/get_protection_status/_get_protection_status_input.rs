// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetProtectionStatusInput {
    /// <p>The ID of the policy for which you want to get the attack information.</p>
    pub policy_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account that is in scope of the policy that you want to get the details for.</p>
    pub member_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The start of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>If you specify a value for <code>MaxResults</code> and you have more objects than the number that you specify for <code>MaxResults</code>, Firewall Manager returns a <code>NextToken</code> value in the response, which you can use to retrieve another group of objects. For the second and subsequent <code>GetProtectionStatus</code> requests, specify the value of <code>NextToken</code> from the previous response to get information about another batch of objects.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the number of objects that you want Firewall Manager to return for this request. If you have more objects than the number that you specify for <code>MaxResults</code>, the response includes a <code>NextToken</code> value that you can use to get another batch of objects.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetProtectionStatusInput {
    /// <p>The ID of the policy for which you want to get the attack information.</p>
    pub fn policy_id(&self) -> ::std::option::Option<&str> {
        self.policy_id.as_deref()
    }
    /// <p>The Amazon Web Services account that is in scope of the policy that you want to get the details for.</p>
    pub fn member_account_id(&self) -> ::std::option::Option<&str> {
        self.member_account_id.as_deref()
    }
    /// <p>The start of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The end of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>If you specify a value for <code>MaxResults</code> and you have more objects than the number that you specify for <code>MaxResults</code>, Firewall Manager returns a <code>NextToken</code> value in the response, which you can use to retrieve another group of objects. For the second and subsequent <code>GetProtectionStatus</code> requests, specify the value of <code>NextToken</code> from the previous response to get information about another batch of objects.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Specifies the number of objects that you want Firewall Manager to return for this request. If you have more objects than the number that you specify for <code>MaxResults</code>, the response includes a <code>NextToken</code> value that you can use to get another batch of objects.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetProtectionStatusInput {
    /// Creates a new builder-style object to manufacture [`GetProtectionStatusInput`](crate::operation::get_protection_status::GetProtectionStatusInput).
    pub fn builder() -> crate::operation::get_protection_status::builders::GetProtectionStatusInputBuilder {
        crate::operation::get_protection_status::builders::GetProtectionStatusInputBuilder::default()
    }
}

/// A builder for [`GetProtectionStatusInput`](crate::operation::get_protection_status::GetProtectionStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetProtectionStatusInputBuilder {
    pub(crate) policy_id: ::std::option::Option<::std::string::String>,
    pub(crate) member_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetProtectionStatusInputBuilder {
    /// <p>The ID of the policy for which you want to get the attack information.</p>
    /// This field is required.
    pub fn policy_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the policy for which you want to get the attack information.</p>
    pub fn set_policy_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_id = input;
        self
    }
    /// <p>The ID of the policy for which you want to get the attack information.</p>
    pub fn get_policy_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_id
    }
    /// <p>The Amazon Web Services account that is in scope of the policy that you want to get the details for.</p>
    pub fn member_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.member_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account that is in scope of the policy that you want to get the details for.</p>
    pub fn set_member_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.member_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account that is in scope of the policy that you want to get the details for.</p>
    pub fn get_member_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.member_account_id
    }
    /// <p>The start of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The end of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end of the time period to query for the attacks. This is a <code>timestamp</code> type. The request syntax listing indicates a <code>number</code> type because the default used by Firewall Manager is Unix time in seconds. However, any valid <code>timestamp</code> format is allowed.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>If you specify a value for <code>MaxResults</code> and you have more objects than the number that you specify for <code>MaxResults</code>, Firewall Manager returns a <code>NextToken</code> value in the response, which you can use to retrieve another group of objects. For the second and subsequent <code>GetProtectionStatus</code> requests, specify the value of <code>NextToken</code> from the previous response to get information about another batch of objects.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you specify a value for <code>MaxResults</code> and you have more objects than the number that you specify for <code>MaxResults</code>, Firewall Manager returns a <code>NextToken</code> value in the response, which you can use to retrieve another group of objects. For the second and subsequent <code>GetProtectionStatus</code> requests, specify the value of <code>NextToken</code> from the previous response to get information about another batch of objects.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If you specify a value for <code>MaxResults</code> and you have more objects than the number that you specify for <code>MaxResults</code>, Firewall Manager returns a <code>NextToken</code> value in the response, which you can use to retrieve another group of objects. For the second and subsequent <code>GetProtectionStatus</code> requests, specify the value of <code>NextToken</code> from the previous response to get information about another batch of objects.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Specifies the number of objects that you want Firewall Manager to return for this request. If you have more objects than the number that you specify for <code>MaxResults</code>, the response includes a <code>NextToken</code> value that you can use to get another batch of objects.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the number of objects that you want Firewall Manager to return for this request. If you have more objects than the number that you specify for <code>MaxResults</code>, the response includes a <code>NextToken</code> value that you can use to get another batch of objects.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Specifies the number of objects that you want Firewall Manager to return for this request. If you have more objects than the number that you specify for <code>MaxResults</code>, the response includes a <code>NextToken</code> value that you can use to get another batch of objects.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetProtectionStatusInput`](crate::operation::get_protection_status::GetProtectionStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_protection_status::GetProtectionStatusInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_protection_status::GetProtectionStatusInput {
            policy_id: self.policy_id,
            member_account_id: self.member_account_id,
            start_time: self.start_time,
            end_time: self.end_time,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
