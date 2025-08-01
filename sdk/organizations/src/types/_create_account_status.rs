// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the status about a <code>CreateAccount</code> or <code>CreateGovCloudAccount</code> request to create an Amazon Web Services account or an Amazon Web Services GovCloud (US) account in an organization.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateAccountStatus {
    /// <p>The unique identifier (ID) that references this request. You get this value from the response of the initial <code>CreateAccount</code> request to create the account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a create account request ID string requires "car-" followed by from 8 to 32 lowercase letters or digits.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The account name given to the account when it was created.</p>
    pub account_name: ::std::option::Option<::std::string::String>,
    /// <p>The status of the asynchronous request to create an Amazon Web Services account.</p>
    pub state: ::std::option::Option<crate::types::CreateAccountState>,
    /// <p>The date and time that the request was made for the account creation.</p>
    pub requested_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the account was created and the request completed.</p>
    pub completed_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for an account ID string requires exactly 12 digits.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account in the Amazon Web Services GovCloud (US) Region.</p>
    pub gov_cloud_account_id: ::std::option::Option<::std::string::String>,
    /// <p>If the request failed, a description of the reason for the failure.</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_LIMIT_EXCEEDED: The account couldn't be created because you reached the limit on the number of accounts in your organization.</p></li>
    /// <li>
    /// <p>CONCURRENT_ACCOUNT_MODIFICATION: You already submitted a request with the same information.</p></li>
    /// <li>
    /// <p>EMAIL_ALREADY_EXISTS: The account could not be created because another Amazon Web Services account with that email address already exists.</p></li>
    /// <li>
    /// <p>FAILED_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization failed to receive business license validation.</p></li>
    /// <li>
    /// <p>GOVCLOUD_ACCOUNT_ALREADY_EXISTS: The account in the Amazon Web Services GovCloud (US) Region could not be created because this Region already includes an account with that email address.</p></li>
    /// <li>
    /// <p>IDENTITY_INVALID_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization can't complete business license validation because it doesn't have valid identity data.</p></li>
    /// <li>
    /// <p>INVALID_ADDRESS: The account could not be created because the address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_EMAIL: The account could not be created because the email address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_PAYMENT_INSTRUMENT: The Amazon Web Services account that owns your organization does not have a supported payment method associated with the account. Amazon Web Services does not support cards issued by financial institutions in Russia or Belarus. For more information, see <a href="https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/manage-general.html">Managing your Amazon Web Services payments</a>.</p></li>
    /// <li>
    /// <p>INTERNAL_FAILURE: The account could not be created because of an internal failure. Try again later. If the problem persists, contact Amazon Web Services Customer Support.</p></li>
    /// <li>
    /// <p>MISSING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has not received Business Validation.</p></li>
    /// <li>
    /// <p>MISSING_PAYMENT_INSTRUMENT: You must configure the management account with a valid payment method, such as a credit card.</p></li>
    /// <li>
    /// <p>PENDING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization is still in the process of completing business license validation.</p></li>
    /// <li>
    /// <p>UNKNOWN_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has an unknown issue with business license validation.</p></li>
    /// </ul>
    pub failure_reason: ::std::option::Option<crate::types::CreateAccountFailureReason>,
}
impl CreateAccountStatus {
    /// <p>The unique identifier (ID) that references this request. You get this value from the response of the initial <code>CreateAccount</code> request to create the account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a create account request ID string requires "car-" followed by from 8 to 32 lowercase letters or digits.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The account name given to the account when it was created.</p>
    pub fn account_name(&self) -> ::std::option::Option<&str> {
        self.account_name.as_deref()
    }
    /// <p>The status of the asynchronous request to create an Amazon Web Services account.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::CreateAccountState> {
        self.state.as_ref()
    }
    /// <p>The date and time that the request was made for the account creation.</p>
    pub fn requested_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.requested_timestamp.as_ref()
    }
    /// <p>The date and time that the account was created and the request completed.</p>
    pub fn completed_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.completed_timestamp.as_ref()
    }
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for an account ID string requires exactly 12 digits.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account in the Amazon Web Services GovCloud (US) Region.</p>
    pub fn gov_cloud_account_id(&self) -> ::std::option::Option<&str> {
        self.gov_cloud_account_id.as_deref()
    }
    /// <p>If the request failed, a description of the reason for the failure.</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_LIMIT_EXCEEDED: The account couldn't be created because you reached the limit on the number of accounts in your organization.</p></li>
    /// <li>
    /// <p>CONCURRENT_ACCOUNT_MODIFICATION: You already submitted a request with the same information.</p></li>
    /// <li>
    /// <p>EMAIL_ALREADY_EXISTS: The account could not be created because another Amazon Web Services account with that email address already exists.</p></li>
    /// <li>
    /// <p>FAILED_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization failed to receive business license validation.</p></li>
    /// <li>
    /// <p>GOVCLOUD_ACCOUNT_ALREADY_EXISTS: The account in the Amazon Web Services GovCloud (US) Region could not be created because this Region already includes an account with that email address.</p></li>
    /// <li>
    /// <p>IDENTITY_INVALID_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization can't complete business license validation because it doesn't have valid identity data.</p></li>
    /// <li>
    /// <p>INVALID_ADDRESS: The account could not be created because the address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_EMAIL: The account could not be created because the email address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_PAYMENT_INSTRUMENT: The Amazon Web Services account that owns your organization does not have a supported payment method associated with the account. Amazon Web Services does not support cards issued by financial institutions in Russia or Belarus. For more information, see <a href="https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/manage-general.html">Managing your Amazon Web Services payments</a>.</p></li>
    /// <li>
    /// <p>INTERNAL_FAILURE: The account could not be created because of an internal failure. Try again later. If the problem persists, contact Amazon Web Services Customer Support.</p></li>
    /// <li>
    /// <p>MISSING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has not received Business Validation.</p></li>
    /// <li>
    /// <p>MISSING_PAYMENT_INSTRUMENT: You must configure the management account with a valid payment method, such as a credit card.</p></li>
    /// <li>
    /// <p>PENDING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization is still in the process of completing business license validation.</p></li>
    /// <li>
    /// <p>UNKNOWN_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has an unknown issue with business license validation.</p></li>
    /// </ul>
    pub fn failure_reason(&self) -> ::std::option::Option<&crate::types::CreateAccountFailureReason> {
        self.failure_reason.as_ref()
    }
}
impl ::std::fmt::Debug for CreateAccountStatus {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAccountStatus");
        formatter.field("id", &self.id);
        formatter.field("account_name", &"*** Sensitive Data Redacted ***");
        formatter.field("state", &self.state);
        formatter.field("requested_timestamp", &self.requested_timestamp);
        formatter.field("completed_timestamp", &self.completed_timestamp);
        formatter.field("account_id", &self.account_id);
        formatter.field("gov_cloud_account_id", &self.gov_cloud_account_id);
        formatter.field("failure_reason", &self.failure_reason);
        formatter.finish()
    }
}
impl CreateAccountStatus {
    /// Creates a new builder-style object to manufacture [`CreateAccountStatus`](crate::types::CreateAccountStatus).
    pub fn builder() -> crate::types::builders::CreateAccountStatusBuilder {
        crate::types::builders::CreateAccountStatusBuilder::default()
    }
}

/// A builder for [`CreateAccountStatus`](crate::types::CreateAccountStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateAccountStatusBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) account_name: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::CreateAccountState>,
    pub(crate) requested_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) completed_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) gov_cloud_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) failure_reason: ::std::option::Option<crate::types::CreateAccountFailureReason>,
}
impl CreateAccountStatusBuilder {
    /// <p>The unique identifier (ID) that references this request. You get this value from the response of the initial <code>CreateAccount</code> request to create the account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a create account request ID string requires "car-" followed by from 8 to 32 lowercase letters or digits.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier (ID) that references this request. You get this value from the response of the initial <code>CreateAccount</code> request to create the account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a create account request ID string requires "car-" followed by from 8 to 32 lowercase letters or digits.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier (ID) that references this request. You get this value from the response of the initial <code>CreateAccount</code> request to create the account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for a create account request ID string requires "car-" followed by from 8 to 32 lowercase letters or digits.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The account name given to the account when it was created.</p>
    pub fn account_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account name given to the account when it was created.</p>
    pub fn set_account_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_name = input;
        self
    }
    /// <p>The account name given to the account when it was created.</p>
    pub fn get_account_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_name
    }
    /// <p>The status of the asynchronous request to create an Amazon Web Services account.</p>
    pub fn state(mut self, input: crate::types::CreateAccountState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the asynchronous request to create an Amazon Web Services account.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::CreateAccountState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The status of the asynchronous request to create an Amazon Web Services account.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::CreateAccountState> {
        &self.state
    }
    /// <p>The date and time that the request was made for the account creation.</p>
    pub fn requested_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.requested_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the request was made for the account creation.</p>
    pub fn set_requested_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.requested_timestamp = input;
        self
    }
    /// <p>The date and time that the request was made for the account creation.</p>
    pub fn get_requested_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.requested_timestamp
    }
    /// <p>The date and time that the account was created and the request completed.</p>
    pub fn completed_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.completed_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the account was created and the request completed.</p>
    pub fn set_completed_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.completed_timestamp = input;
        self
    }
    /// <p>The date and time that the account was created and the request completed.</p>
    pub fn get_completed_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.completed_timestamp
    }
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for an account ID string requires exactly 12 digits.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for an account ID string requires exactly 12 digits.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> for an account ID string requires exactly 12 digits.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account in the Amazon Web Services GovCloud (US) Region.</p>
    pub fn gov_cloud_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gov_cloud_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account in the Amazon Web Services GovCloud (US) Region.</p>
    pub fn set_gov_cloud_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gov_cloud_account_id = input;
        self
    }
    /// <p>If the account was created successfully, the unique identifier (ID) of the new account in the Amazon Web Services GovCloud (US) Region.</p>
    pub fn get_gov_cloud_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.gov_cloud_account_id
    }
    /// <p>If the request failed, a description of the reason for the failure.</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_LIMIT_EXCEEDED: The account couldn't be created because you reached the limit on the number of accounts in your organization.</p></li>
    /// <li>
    /// <p>CONCURRENT_ACCOUNT_MODIFICATION: You already submitted a request with the same information.</p></li>
    /// <li>
    /// <p>EMAIL_ALREADY_EXISTS: The account could not be created because another Amazon Web Services account with that email address already exists.</p></li>
    /// <li>
    /// <p>FAILED_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization failed to receive business license validation.</p></li>
    /// <li>
    /// <p>GOVCLOUD_ACCOUNT_ALREADY_EXISTS: The account in the Amazon Web Services GovCloud (US) Region could not be created because this Region already includes an account with that email address.</p></li>
    /// <li>
    /// <p>IDENTITY_INVALID_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization can't complete business license validation because it doesn't have valid identity data.</p></li>
    /// <li>
    /// <p>INVALID_ADDRESS: The account could not be created because the address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_EMAIL: The account could not be created because the email address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_PAYMENT_INSTRUMENT: The Amazon Web Services account that owns your organization does not have a supported payment method associated with the account. Amazon Web Services does not support cards issued by financial institutions in Russia or Belarus. For more information, see <a href="https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/manage-general.html">Managing your Amazon Web Services payments</a>.</p></li>
    /// <li>
    /// <p>INTERNAL_FAILURE: The account could not be created because of an internal failure. Try again later. If the problem persists, contact Amazon Web Services Customer Support.</p></li>
    /// <li>
    /// <p>MISSING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has not received Business Validation.</p></li>
    /// <li>
    /// <p>MISSING_PAYMENT_INSTRUMENT: You must configure the management account with a valid payment method, such as a credit card.</p></li>
    /// <li>
    /// <p>PENDING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization is still in the process of completing business license validation.</p></li>
    /// <li>
    /// <p>UNKNOWN_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has an unknown issue with business license validation.</p></li>
    /// </ul>
    pub fn failure_reason(mut self, input: crate::types::CreateAccountFailureReason) -> Self {
        self.failure_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the request failed, a description of the reason for the failure.</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_LIMIT_EXCEEDED: The account couldn't be created because you reached the limit on the number of accounts in your organization.</p></li>
    /// <li>
    /// <p>CONCURRENT_ACCOUNT_MODIFICATION: You already submitted a request with the same information.</p></li>
    /// <li>
    /// <p>EMAIL_ALREADY_EXISTS: The account could not be created because another Amazon Web Services account with that email address already exists.</p></li>
    /// <li>
    /// <p>FAILED_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization failed to receive business license validation.</p></li>
    /// <li>
    /// <p>GOVCLOUD_ACCOUNT_ALREADY_EXISTS: The account in the Amazon Web Services GovCloud (US) Region could not be created because this Region already includes an account with that email address.</p></li>
    /// <li>
    /// <p>IDENTITY_INVALID_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization can't complete business license validation because it doesn't have valid identity data.</p></li>
    /// <li>
    /// <p>INVALID_ADDRESS: The account could not be created because the address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_EMAIL: The account could not be created because the email address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_PAYMENT_INSTRUMENT: The Amazon Web Services account that owns your organization does not have a supported payment method associated with the account. Amazon Web Services does not support cards issued by financial institutions in Russia or Belarus. For more information, see <a href="https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/manage-general.html">Managing your Amazon Web Services payments</a>.</p></li>
    /// <li>
    /// <p>INTERNAL_FAILURE: The account could not be created because of an internal failure. Try again later. If the problem persists, contact Amazon Web Services Customer Support.</p></li>
    /// <li>
    /// <p>MISSING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has not received Business Validation.</p></li>
    /// <li>
    /// <p>MISSING_PAYMENT_INSTRUMENT: You must configure the management account with a valid payment method, such as a credit card.</p></li>
    /// <li>
    /// <p>PENDING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization is still in the process of completing business license validation.</p></li>
    /// <li>
    /// <p>UNKNOWN_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has an unknown issue with business license validation.</p></li>
    /// </ul>
    pub fn set_failure_reason(mut self, input: ::std::option::Option<crate::types::CreateAccountFailureReason>) -> Self {
        self.failure_reason = input;
        self
    }
    /// <p>If the request failed, a description of the reason for the failure.</p>
    /// <ul>
    /// <li>
    /// <p>ACCOUNT_LIMIT_EXCEEDED: The account couldn't be created because you reached the limit on the number of accounts in your organization.</p></li>
    /// <li>
    /// <p>CONCURRENT_ACCOUNT_MODIFICATION: You already submitted a request with the same information.</p></li>
    /// <li>
    /// <p>EMAIL_ALREADY_EXISTS: The account could not be created because another Amazon Web Services account with that email address already exists.</p></li>
    /// <li>
    /// <p>FAILED_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization failed to receive business license validation.</p></li>
    /// <li>
    /// <p>GOVCLOUD_ACCOUNT_ALREADY_EXISTS: The account in the Amazon Web Services GovCloud (US) Region could not be created because this Region already includes an account with that email address.</p></li>
    /// <li>
    /// <p>IDENTITY_INVALID_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization can't complete business license validation because it doesn't have valid identity data.</p></li>
    /// <li>
    /// <p>INVALID_ADDRESS: The account could not be created because the address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_EMAIL: The account could not be created because the email address you provided is not valid.</p></li>
    /// <li>
    /// <p>INVALID_PAYMENT_INSTRUMENT: The Amazon Web Services account that owns your organization does not have a supported payment method associated with the account. Amazon Web Services does not support cards issued by financial institutions in Russia or Belarus. For more information, see <a href="https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/manage-general.html">Managing your Amazon Web Services payments</a>.</p></li>
    /// <li>
    /// <p>INTERNAL_FAILURE: The account could not be created because of an internal failure. Try again later. If the problem persists, contact Amazon Web Services Customer Support.</p></li>
    /// <li>
    /// <p>MISSING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has not received Business Validation.</p></li>
    /// <li>
    /// <p>MISSING_PAYMENT_INSTRUMENT: You must configure the management account with a valid payment method, such as a credit card.</p></li>
    /// <li>
    /// <p>PENDING_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization is still in the process of completing business license validation.</p></li>
    /// <li>
    /// <p>UNKNOWN_BUSINESS_VALIDATION: The Amazon Web Services account that owns your organization has an unknown issue with business license validation.</p></li>
    /// </ul>
    pub fn get_failure_reason(&self) -> &::std::option::Option<crate::types::CreateAccountFailureReason> {
        &self.failure_reason
    }
    /// Consumes the builder and constructs a [`CreateAccountStatus`](crate::types::CreateAccountStatus).
    pub fn build(self) -> crate::types::CreateAccountStatus {
        crate::types::CreateAccountStatus {
            id: self.id,
            account_name: self.account_name,
            state: self.state,
            requested_timestamp: self.requested_timestamp,
            completed_timestamp: self.completed_timestamp,
            account_id: self.account_id,
            gov_cloud_account_id: self.gov_cloud_account_id,
            failure_reason: self.failure_reason,
        }
    }
}
impl ::std::fmt::Debug for CreateAccountStatusBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAccountStatusBuilder");
        formatter.field("id", &self.id);
        formatter.field("account_name", &"*** Sensitive Data Redacted ***");
        formatter.field("state", &self.state);
        formatter.field("requested_timestamp", &self.requested_timestamp);
        formatter.field("completed_timestamp", &self.completed_timestamp);
        formatter.field("account_id", &self.account_id);
        formatter.field("gov_cloud_account_id", &self.gov_cloud_account_id);
        formatter.field("failure_reason", &self.failure_reason);
        formatter.finish()
    }
}
