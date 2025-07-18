// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRateBasedRuleOutput {
    /// <p>The <code>ChangeToken</code> that you used to submit the <code>DeleteRateBasedRule</code> request. You can also use this value to query the status of the request. For more information, see <code>GetChangeTokenStatus</code>.</p>
    pub change_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteRateBasedRuleOutput {
    /// <p>The <code>ChangeToken</code> that you used to submit the <code>DeleteRateBasedRule</code> request. You can also use this value to query the status of the request. For more information, see <code>GetChangeTokenStatus</code>.</p>
    pub fn change_token(&self) -> ::std::option::Option<&str> {
        self.change_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteRateBasedRuleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteRateBasedRuleOutput {
    /// Creates a new builder-style object to manufacture [`DeleteRateBasedRuleOutput`](crate::operation::delete_rate_based_rule::DeleteRateBasedRuleOutput).
    pub fn builder() -> crate::operation::delete_rate_based_rule::builders::DeleteRateBasedRuleOutputBuilder {
        crate::operation::delete_rate_based_rule::builders::DeleteRateBasedRuleOutputBuilder::default()
    }
}

/// A builder for [`DeleteRateBasedRuleOutput`](crate::operation::delete_rate_based_rule::DeleteRateBasedRuleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRateBasedRuleOutputBuilder {
    pub(crate) change_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteRateBasedRuleOutputBuilder {
    /// <p>The <code>ChangeToken</code> that you used to submit the <code>DeleteRateBasedRule</code> request. You can also use this value to query the status of the request. For more information, see <code>GetChangeTokenStatus</code>.</p>
    pub fn change_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>ChangeToken</code> that you used to submit the <code>DeleteRateBasedRule</code> request. You can also use this value to query the status of the request. For more information, see <code>GetChangeTokenStatus</code>.</p>
    pub fn set_change_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_token = input;
        self
    }
    /// <p>The <code>ChangeToken</code> that you used to submit the <code>DeleteRateBasedRule</code> request. You can also use this value to query the status of the request. For more information, see <code>GetChangeTokenStatus</code>.</p>
    pub fn get_change_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteRateBasedRuleOutput`](crate::operation::delete_rate_based_rule::DeleteRateBasedRuleOutput).
    pub fn build(self) -> crate::operation::delete_rate_based_rule::DeleteRateBasedRuleOutput {
        crate::operation::delete_rate_based_rule::DeleteRateBasedRuleOutput {
            change_token: self.change_token,
            _request_id: self._request_id,
        }
    }
}
