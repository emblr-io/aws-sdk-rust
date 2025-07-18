// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RequestServiceQuotaIncreaseInput {
    /// <p>Specifies the service identifier. To find the service code value for an Amazon Web Services service, use the <code>ListServices</code> operation.</p>
    pub service_code: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the quota identifier. To find the quota code for a specific quota, use the <code>ListServiceQuotas</code> operation, and look for the <code>QuotaCode</code> response in the output for the quota you want.</p>
    pub quota_code: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the new, increased value for the quota.</p>
    pub desired_value: ::std::option::Option<f64>,
    /// <p>Specifies the resource with an Amazon Resource Name (ARN).</p>
    pub context_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies if an Amazon Web Services Support case can be opened for the quota increase request. This parameter is optional.</p>
    /// <p>By default, this flag is set to <code>True</code> and Amazon Web Services may create a support case for some quota increase requests. You can set this flag to <code>False</code> if you do not want a support case created when you request a quota increase. If you set the flag to <code>False</code>, Amazon Web Services does not open a support case and updates the request status to <code>Not approved</code>.</p>
    pub support_case_allowed: ::std::option::Option<bool>,
}
impl RequestServiceQuotaIncreaseInput {
    /// <p>Specifies the service identifier. To find the service code value for an Amazon Web Services service, use the <code>ListServices</code> operation.</p>
    pub fn service_code(&self) -> ::std::option::Option<&str> {
        self.service_code.as_deref()
    }
    /// <p>Specifies the quota identifier. To find the quota code for a specific quota, use the <code>ListServiceQuotas</code> operation, and look for the <code>QuotaCode</code> response in the output for the quota you want.</p>
    pub fn quota_code(&self) -> ::std::option::Option<&str> {
        self.quota_code.as_deref()
    }
    /// <p>Specifies the new, increased value for the quota.</p>
    pub fn desired_value(&self) -> ::std::option::Option<f64> {
        self.desired_value
    }
    /// <p>Specifies the resource with an Amazon Resource Name (ARN).</p>
    pub fn context_id(&self) -> ::std::option::Option<&str> {
        self.context_id.as_deref()
    }
    /// <p>Specifies if an Amazon Web Services Support case can be opened for the quota increase request. This parameter is optional.</p>
    /// <p>By default, this flag is set to <code>True</code> and Amazon Web Services may create a support case for some quota increase requests. You can set this flag to <code>False</code> if you do not want a support case created when you request a quota increase. If you set the flag to <code>False</code>, Amazon Web Services does not open a support case and updates the request status to <code>Not approved</code>.</p>
    pub fn support_case_allowed(&self) -> ::std::option::Option<bool> {
        self.support_case_allowed
    }
}
impl RequestServiceQuotaIncreaseInput {
    /// Creates a new builder-style object to manufacture [`RequestServiceQuotaIncreaseInput`](crate::operation::request_service_quota_increase::RequestServiceQuotaIncreaseInput).
    pub fn builder() -> crate::operation::request_service_quota_increase::builders::RequestServiceQuotaIncreaseInputBuilder {
        crate::operation::request_service_quota_increase::builders::RequestServiceQuotaIncreaseInputBuilder::default()
    }
}

/// A builder for [`RequestServiceQuotaIncreaseInput`](crate::operation::request_service_quota_increase::RequestServiceQuotaIncreaseInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RequestServiceQuotaIncreaseInputBuilder {
    pub(crate) service_code: ::std::option::Option<::std::string::String>,
    pub(crate) quota_code: ::std::option::Option<::std::string::String>,
    pub(crate) desired_value: ::std::option::Option<f64>,
    pub(crate) context_id: ::std::option::Option<::std::string::String>,
    pub(crate) support_case_allowed: ::std::option::Option<bool>,
}
impl RequestServiceQuotaIncreaseInputBuilder {
    /// <p>Specifies the service identifier. To find the service code value for an Amazon Web Services service, use the <code>ListServices</code> operation.</p>
    /// This field is required.
    pub fn service_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the service identifier. To find the service code value for an Amazon Web Services service, use the <code>ListServices</code> operation.</p>
    pub fn set_service_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_code = input;
        self
    }
    /// <p>Specifies the service identifier. To find the service code value for an Amazon Web Services service, use the <code>ListServices</code> operation.</p>
    pub fn get_service_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_code
    }
    /// <p>Specifies the quota identifier. To find the quota code for a specific quota, use the <code>ListServiceQuotas</code> operation, and look for the <code>QuotaCode</code> response in the output for the quota you want.</p>
    /// This field is required.
    pub fn quota_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.quota_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the quota identifier. To find the quota code for a specific quota, use the <code>ListServiceQuotas</code> operation, and look for the <code>QuotaCode</code> response in the output for the quota you want.</p>
    pub fn set_quota_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.quota_code = input;
        self
    }
    /// <p>Specifies the quota identifier. To find the quota code for a specific quota, use the <code>ListServiceQuotas</code> operation, and look for the <code>QuotaCode</code> response in the output for the quota you want.</p>
    pub fn get_quota_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.quota_code
    }
    /// <p>Specifies the new, increased value for the quota.</p>
    /// This field is required.
    pub fn desired_value(mut self, input: f64) -> Self {
        self.desired_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the new, increased value for the quota.</p>
    pub fn set_desired_value(mut self, input: ::std::option::Option<f64>) -> Self {
        self.desired_value = input;
        self
    }
    /// <p>Specifies the new, increased value for the quota.</p>
    pub fn get_desired_value(&self) -> &::std::option::Option<f64> {
        &self.desired_value
    }
    /// <p>Specifies the resource with an Amazon Resource Name (ARN).</p>
    pub fn context_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.context_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the resource with an Amazon Resource Name (ARN).</p>
    pub fn set_context_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.context_id = input;
        self
    }
    /// <p>Specifies the resource with an Amazon Resource Name (ARN).</p>
    pub fn get_context_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.context_id
    }
    /// <p>Specifies if an Amazon Web Services Support case can be opened for the quota increase request. This parameter is optional.</p>
    /// <p>By default, this flag is set to <code>True</code> and Amazon Web Services may create a support case for some quota increase requests. You can set this flag to <code>False</code> if you do not want a support case created when you request a quota increase. If you set the flag to <code>False</code>, Amazon Web Services does not open a support case and updates the request status to <code>Not approved</code>.</p>
    pub fn support_case_allowed(mut self, input: bool) -> Self {
        self.support_case_allowed = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if an Amazon Web Services Support case can be opened for the quota increase request. This parameter is optional.</p>
    /// <p>By default, this flag is set to <code>True</code> and Amazon Web Services may create a support case for some quota increase requests. You can set this flag to <code>False</code> if you do not want a support case created when you request a quota increase. If you set the flag to <code>False</code>, Amazon Web Services does not open a support case and updates the request status to <code>Not approved</code>.</p>
    pub fn set_support_case_allowed(mut self, input: ::std::option::Option<bool>) -> Self {
        self.support_case_allowed = input;
        self
    }
    /// <p>Specifies if an Amazon Web Services Support case can be opened for the quota increase request. This parameter is optional.</p>
    /// <p>By default, this flag is set to <code>True</code> and Amazon Web Services may create a support case for some quota increase requests. You can set this flag to <code>False</code> if you do not want a support case created when you request a quota increase. If you set the flag to <code>False</code>, Amazon Web Services does not open a support case and updates the request status to <code>Not approved</code>.</p>
    pub fn get_support_case_allowed(&self) -> &::std::option::Option<bool> {
        &self.support_case_allowed
    }
    /// Consumes the builder and constructs a [`RequestServiceQuotaIncreaseInput`](crate::operation::request_service_quota_increase::RequestServiceQuotaIncreaseInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::request_service_quota_increase::RequestServiceQuotaIncreaseInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::request_service_quota_increase::RequestServiceQuotaIncreaseInput {
            service_code: self.service_code,
            quota_code: self.quota_code,
            desired_value: self.desired_value,
            context_id: self.context_id,
            support_case_allowed: self.support_case_allowed,
        })
    }
}
