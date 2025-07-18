// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteResourceShareOutput {
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub return_value: ::std::option::Option<bool>,
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteResourceShareOutput {
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub fn return_value(&self) -> ::std::option::Option<bool> {
        self.return_value
    }
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteResourceShareOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteResourceShareOutput {
    /// Creates a new builder-style object to manufacture [`DeleteResourceShareOutput`](crate::operation::delete_resource_share::DeleteResourceShareOutput).
    pub fn builder() -> crate::operation::delete_resource_share::builders::DeleteResourceShareOutputBuilder {
        crate::operation::delete_resource_share::builders::DeleteResourceShareOutputBuilder::default()
    }
}

/// A builder for [`DeleteResourceShareOutput`](crate::operation::delete_resource_share::DeleteResourceShareOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteResourceShareOutputBuilder {
    pub(crate) return_value: ::std::option::Option<bool>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteResourceShareOutputBuilder {
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub fn return_value(mut self, input: bool) -> Self {
        self.return_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub fn set_return_value(mut self, input: ::std::option::Option<bool>) -> Self {
        self.return_value = input;
        self
    }
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub fn get_return_value(&self) -> &::std::option::Option<bool> {
        &self.return_value
    }
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The idempotency identifier associated with this request. If you want to repeat the same operation in an idempotent manner then you must include this value in the <code>clientToken</code> request parameter of that later call. All other parameters must also have the same values that you used in the first call.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteResourceShareOutput`](crate::operation::delete_resource_share::DeleteResourceShareOutput).
    pub fn build(self) -> crate::operation::delete_resource_share::DeleteResourceShareOutput {
        crate::operation::delete_resource_share::DeleteResourceShareOutput {
            return_value: self.return_value,
            client_token: self.client_token,
            _request_id: self._request_id,
        }
    }
}
