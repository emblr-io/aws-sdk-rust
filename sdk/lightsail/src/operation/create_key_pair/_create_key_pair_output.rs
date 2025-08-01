// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateKeyPairOutput {
    /// <p>An array of key-value pairs containing information about the new key pair you just created.</p>
    pub key_pair: ::std::option::Option<crate::types::KeyPair>,
    /// <p>A base64-encoded public key of the <code>ssh-rsa</code> type.</p>
    pub public_key_base64: ::std::option::Option<::std::string::String>,
    /// <p>A base64-encoded RSA private key.</p>
    pub private_key_base64: ::std::option::Option<::std::string::String>,
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub operation: ::std::option::Option<crate::types::Operation>,
    _request_id: Option<String>,
}
impl CreateKeyPairOutput {
    /// <p>An array of key-value pairs containing information about the new key pair you just created.</p>
    pub fn key_pair(&self) -> ::std::option::Option<&crate::types::KeyPair> {
        self.key_pair.as_ref()
    }
    /// <p>A base64-encoded public key of the <code>ssh-rsa</code> type.</p>
    pub fn public_key_base64(&self) -> ::std::option::Option<&str> {
        self.public_key_base64.as_deref()
    }
    /// <p>A base64-encoded RSA private key.</p>
    pub fn private_key_base64(&self) -> ::std::option::Option<&str> {
        self.private_key_base64.as_deref()
    }
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub fn operation(&self) -> ::std::option::Option<&crate::types::Operation> {
        self.operation.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateKeyPairOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateKeyPairOutput {
    /// Creates a new builder-style object to manufacture [`CreateKeyPairOutput`](crate::operation::create_key_pair::CreateKeyPairOutput).
    pub fn builder() -> crate::operation::create_key_pair::builders::CreateKeyPairOutputBuilder {
        crate::operation::create_key_pair::builders::CreateKeyPairOutputBuilder::default()
    }
}

/// A builder for [`CreateKeyPairOutput`](crate::operation::create_key_pair::CreateKeyPairOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateKeyPairOutputBuilder {
    pub(crate) key_pair: ::std::option::Option<crate::types::KeyPair>,
    pub(crate) public_key_base64: ::std::option::Option<::std::string::String>,
    pub(crate) private_key_base64: ::std::option::Option<::std::string::String>,
    pub(crate) operation: ::std::option::Option<crate::types::Operation>,
    _request_id: Option<String>,
}
impl CreateKeyPairOutputBuilder {
    /// <p>An array of key-value pairs containing information about the new key pair you just created.</p>
    pub fn key_pair(mut self, input: crate::types::KeyPair) -> Self {
        self.key_pair = ::std::option::Option::Some(input);
        self
    }
    /// <p>An array of key-value pairs containing information about the new key pair you just created.</p>
    pub fn set_key_pair(mut self, input: ::std::option::Option<crate::types::KeyPair>) -> Self {
        self.key_pair = input;
        self
    }
    /// <p>An array of key-value pairs containing information about the new key pair you just created.</p>
    pub fn get_key_pair(&self) -> &::std::option::Option<crate::types::KeyPair> {
        &self.key_pair
    }
    /// <p>A base64-encoded public key of the <code>ssh-rsa</code> type.</p>
    pub fn public_key_base64(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.public_key_base64 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A base64-encoded public key of the <code>ssh-rsa</code> type.</p>
    pub fn set_public_key_base64(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.public_key_base64 = input;
        self
    }
    /// <p>A base64-encoded public key of the <code>ssh-rsa</code> type.</p>
    pub fn get_public_key_base64(&self) -> &::std::option::Option<::std::string::String> {
        &self.public_key_base64
    }
    /// <p>A base64-encoded RSA private key.</p>
    pub fn private_key_base64(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.private_key_base64 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A base64-encoded RSA private key.</p>
    pub fn set_private_key_base64(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.private_key_base64 = input;
        self
    }
    /// <p>A base64-encoded RSA private key.</p>
    pub fn get_private_key_base64(&self) -> &::std::option::Option<::std::string::String> {
        &self.private_key_base64
    }
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub fn operation(mut self, input: crate::types::Operation) -> Self {
        self.operation = ::std::option::Option::Some(input);
        self
    }
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub fn set_operation(mut self, input: ::std::option::Option<crate::types::Operation>) -> Self {
        self.operation = input;
        self
    }
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub fn get_operation(&self) -> &::std::option::Option<crate::types::Operation> {
        &self.operation
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateKeyPairOutput`](crate::operation::create_key_pair::CreateKeyPairOutput).
    pub fn build(self) -> crate::operation::create_key_pair::CreateKeyPairOutput {
        crate::operation::create_key_pair::CreateKeyPairOutput {
            key_pair: self.key_pair,
            public_key_base64: self.public_key_base64,
            private_key_base64: self.private_key_base64,
            operation: self.operation,
            _request_id: self._request_id,
        }
    }
}
