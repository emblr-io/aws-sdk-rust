// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutKeywordOutput {
    /// <p>The PhoneNumberArn or PoolArn that the keyword was associated with.</p>
    pub origination_identity_arn: ::std::option::Option<::std::string::String>,
    /// <p>The PhoneNumberId or PoolId that the keyword was associated with.</p>
    pub origination_identity: ::std::option::Option<::std::string::String>,
    /// <p>The keyword that was added.</p>
    pub keyword: ::std::option::Option<::std::string::String>,
    /// <p>The message associated with the keyword.</p>
    pub keyword_message: ::std::option::Option<::std::string::String>,
    /// <p>The action to perform when the keyword is used.</p>
    pub keyword_action: ::std::option::Option<crate::types::KeywordAction>,
    _request_id: Option<String>,
}
impl PutKeywordOutput {
    /// <p>The PhoneNumberArn or PoolArn that the keyword was associated with.</p>
    pub fn origination_identity_arn(&self) -> ::std::option::Option<&str> {
        self.origination_identity_arn.as_deref()
    }
    /// <p>The PhoneNumberId or PoolId that the keyword was associated with.</p>
    pub fn origination_identity(&self) -> ::std::option::Option<&str> {
        self.origination_identity.as_deref()
    }
    /// <p>The keyword that was added.</p>
    pub fn keyword(&self) -> ::std::option::Option<&str> {
        self.keyword.as_deref()
    }
    /// <p>The message associated with the keyword.</p>
    pub fn keyword_message(&self) -> ::std::option::Option<&str> {
        self.keyword_message.as_deref()
    }
    /// <p>The action to perform when the keyword is used.</p>
    pub fn keyword_action(&self) -> ::std::option::Option<&crate::types::KeywordAction> {
        self.keyword_action.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutKeywordOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutKeywordOutput {
    /// Creates a new builder-style object to manufacture [`PutKeywordOutput`](crate::operation::put_keyword::PutKeywordOutput).
    pub fn builder() -> crate::operation::put_keyword::builders::PutKeywordOutputBuilder {
        crate::operation::put_keyword::builders::PutKeywordOutputBuilder::default()
    }
}

/// A builder for [`PutKeywordOutput`](crate::operation::put_keyword::PutKeywordOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutKeywordOutputBuilder {
    pub(crate) origination_identity_arn: ::std::option::Option<::std::string::String>,
    pub(crate) origination_identity: ::std::option::Option<::std::string::String>,
    pub(crate) keyword: ::std::option::Option<::std::string::String>,
    pub(crate) keyword_message: ::std::option::Option<::std::string::String>,
    pub(crate) keyword_action: ::std::option::Option<crate::types::KeywordAction>,
    _request_id: Option<String>,
}
impl PutKeywordOutputBuilder {
    /// <p>The PhoneNumberArn or PoolArn that the keyword was associated with.</p>
    pub fn origination_identity_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.origination_identity_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The PhoneNumberArn or PoolArn that the keyword was associated with.</p>
    pub fn set_origination_identity_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.origination_identity_arn = input;
        self
    }
    /// <p>The PhoneNumberArn or PoolArn that the keyword was associated with.</p>
    pub fn get_origination_identity_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.origination_identity_arn
    }
    /// <p>The PhoneNumberId or PoolId that the keyword was associated with.</p>
    pub fn origination_identity(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.origination_identity = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The PhoneNumberId or PoolId that the keyword was associated with.</p>
    pub fn set_origination_identity(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.origination_identity = input;
        self
    }
    /// <p>The PhoneNumberId or PoolId that the keyword was associated with.</p>
    pub fn get_origination_identity(&self) -> &::std::option::Option<::std::string::String> {
        &self.origination_identity
    }
    /// <p>The keyword that was added.</p>
    pub fn keyword(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.keyword = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The keyword that was added.</p>
    pub fn set_keyword(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.keyword = input;
        self
    }
    /// <p>The keyword that was added.</p>
    pub fn get_keyword(&self) -> &::std::option::Option<::std::string::String> {
        &self.keyword
    }
    /// <p>The message associated with the keyword.</p>
    pub fn keyword_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.keyword_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message associated with the keyword.</p>
    pub fn set_keyword_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.keyword_message = input;
        self
    }
    /// <p>The message associated with the keyword.</p>
    pub fn get_keyword_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.keyword_message
    }
    /// <p>The action to perform when the keyword is used.</p>
    pub fn keyword_action(mut self, input: crate::types::KeywordAction) -> Self {
        self.keyword_action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action to perform when the keyword is used.</p>
    pub fn set_keyword_action(mut self, input: ::std::option::Option<crate::types::KeywordAction>) -> Self {
        self.keyword_action = input;
        self
    }
    /// <p>The action to perform when the keyword is used.</p>
    pub fn get_keyword_action(&self) -> &::std::option::Option<crate::types::KeywordAction> {
        &self.keyword_action
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutKeywordOutput`](crate::operation::put_keyword::PutKeywordOutput).
    pub fn build(self) -> crate::operation::put_keyword::PutKeywordOutput {
        crate::operation::put_keyword::PutKeywordOutput {
            origination_identity_arn: self.origination_identity_arn,
            origination_identity: self.origination_identity,
            keyword: self.keyword,
            keyword_message: self.keyword_message,
            keyword_action: self.keyword_action,
            _request_id: self._request_id,
        }
    }
}
