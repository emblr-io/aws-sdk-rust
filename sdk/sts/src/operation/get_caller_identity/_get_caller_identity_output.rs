// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the response to a successful <code>GetCallerIdentity</code> request, including information about the entity making the request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCallerIdentityOutput {
    /// <p>The unique identifier of the calling entity. The exact value depends on the type of entity that is making the call. The values returned are those listed in the <b>aws:userid</b> column in the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable">Principal table</a> found on the <b>Policy Variables</b> reference page in the <i>IAM User Guide</i>.</p>
    pub user_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID number of the account that owns or contains the calling entity.</p>
    pub account: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services ARN associated with the calling entity.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetCallerIdentityOutput {
    /// <p>The unique identifier of the calling entity. The exact value depends on the type of entity that is making the call. The values returned are those listed in the <b>aws:userid</b> column in the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable">Principal table</a> found on the <b>Policy Variables</b> reference page in the <i>IAM User Guide</i>.</p>
    pub fn user_id(&self) -> ::std::option::Option<&str> {
        self.user_id.as_deref()
    }
    /// <p>The Amazon Web Services account ID number of the account that owns or contains the calling entity.</p>
    pub fn account(&self) -> ::std::option::Option<&str> {
        self.account.as_deref()
    }
    /// <p>The Amazon Web Services ARN associated with the calling entity.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetCallerIdentityOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetCallerIdentityOutput {
    /// Creates a new builder-style object to manufacture [`GetCallerIdentityOutput`](crate::operation::get_caller_identity::GetCallerIdentityOutput).
    pub fn builder() -> crate::operation::get_caller_identity::builders::GetCallerIdentityOutputBuilder {
        crate::operation::get_caller_identity::builders::GetCallerIdentityOutputBuilder::default()
    }
}

/// A builder for [`GetCallerIdentityOutput`](crate::operation::get_caller_identity::GetCallerIdentityOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCallerIdentityOutputBuilder {
    pub(crate) user_id: ::std::option::Option<::std::string::String>,
    pub(crate) account: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetCallerIdentityOutputBuilder {
    /// <p>The unique identifier of the calling entity. The exact value depends on the type of entity that is making the call. The values returned are those listed in the <b>aws:userid</b> column in the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable">Principal table</a> found on the <b>Policy Variables</b> reference page in the <i>IAM User Guide</i>.</p>
    pub fn user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the calling entity. The exact value depends on the type of entity that is making the call. The values returned are those listed in the <b>aws:userid</b> column in the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable">Principal table</a> found on the <b>Policy Variables</b> reference page in the <i>IAM User Guide</i>.</p>
    pub fn set_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_id = input;
        self
    }
    /// <p>The unique identifier of the calling entity. The exact value depends on the type of entity that is making the call. The values returned are those listed in the <b>aws:userid</b> column in the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable">Principal table</a> found on the <b>Policy Variables</b> reference page in the <i>IAM User Guide</i>.</p>
    pub fn get_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_id
    }
    /// <p>The Amazon Web Services account ID number of the account that owns or contains the calling entity.</p>
    pub fn account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID number of the account that owns or contains the calling entity.</p>
    pub fn set_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account = input;
        self
    }
    /// <p>The Amazon Web Services account ID number of the account that owns or contains the calling entity.</p>
    pub fn get_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.account
    }
    /// <p>The Amazon Web Services ARN associated with the calling entity.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services ARN associated with the calling entity.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Web Services ARN associated with the calling entity.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetCallerIdentityOutput`](crate::operation::get_caller_identity::GetCallerIdentityOutput).
    pub fn build(self) -> crate::operation::get_caller_identity::GetCallerIdentityOutput {
        crate::operation::get_caller_identity::GetCallerIdentityOutput {
            user_id: self.user_id,
            account: self.account,
            arn: self.arn,
            _request_id: self._request_id,
        }
    }
}
