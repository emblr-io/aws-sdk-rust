// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteIpSetInput {
    /// <p>The <code>IPSetId</code> of the <code>IPSet</code> that you want to delete. <code>IPSetId</code> is returned by <code>CreateIPSet</code> and by <code>ListIPSets</code>.</p>
    pub ip_set_id: ::std::option::Option<::std::string::String>,
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub change_token: ::std::option::Option<::std::string::String>,
}
impl DeleteIpSetInput {
    /// <p>The <code>IPSetId</code> of the <code>IPSet</code> that you want to delete. <code>IPSetId</code> is returned by <code>CreateIPSet</code> and by <code>ListIPSets</code>.</p>
    pub fn ip_set_id(&self) -> ::std::option::Option<&str> {
        self.ip_set_id.as_deref()
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn change_token(&self) -> ::std::option::Option<&str> {
        self.change_token.as_deref()
    }
}
impl DeleteIpSetInput {
    /// Creates a new builder-style object to manufacture [`DeleteIpSetInput`](crate::operation::delete_ip_set::DeleteIpSetInput).
    pub fn builder() -> crate::operation::delete_ip_set::builders::DeleteIpSetInputBuilder {
        crate::operation::delete_ip_set::builders::DeleteIpSetInputBuilder::default()
    }
}

/// A builder for [`DeleteIpSetInput`](crate::operation::delete_ip_set::DeleteIpSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteIpSetInputBuilder {
    pub(crate) ip_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) change_token: ::std::option::Option<::std::string::String>,
}
impl DeleteIpSetInputBuilder {
    /// <p>The <code>IPSetId</code> of the <code>IPSet</code> that you want to delete. <code>IPSetId</code> is returned by <code>CreateIPSet</code> and by <code>ListIPSets</code>.</p>
    /// This field is required.
    pub fn ip_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>IPSetId</code> of the <code>IPSet</code> that you want to delete. <code>IPSetId</code> is returned by <code>CreateIPSet</code> and by <code>ListIPSets</code>.</p>
    pub fn set_ip_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip_set_id = input;
        self
    }
    /// <p>The <code>IPSetId</code> of the <code>IPSet</code> that you want to delete. <code>IPSetId</code> is returned by <code>CreateIPSet</code> and by <code>ListIPSets</code>.</p>
    pub fn get_ip_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip_set_id
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    /// This field is required.
    pub fn change_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn set_change_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_token = input;
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn get_change_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_token
    }
    /// Consumes the builder and constructs a [`DeleteIpSetInput`](crate::operation::delete_ip_set::DeleteIpSetInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_ip_set::DeleteIpSetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_ip_set::DeleteIpSetInput {
            ip_set_id: self.ip_set_id,
            change_token: self.change_token,
        })
    }
}
