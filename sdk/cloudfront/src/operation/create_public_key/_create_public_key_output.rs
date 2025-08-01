// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePublicKeyOutput {
    /// <p>The public key.</p>
    pub public_key: ::std::option::Option<crate::types::PublicKey>,
    /// <p>The URL of the public key.</p>
    pub location: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for this version of the public key.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreatePublicKeyOutput {
    /// <p>The public key.</p>
    pub fn public_key(&self) -> ::std::option::Option<&crate::types::PublicKey> {
        self.public_key.as_ref()
    }
    /// <p>The URL of the public key.</p>
    pub fn location(&self) -> ::std::option::Option<&str> {
        self.location.as_deref()
    }
    /// <p>The identifier for this version of the public key.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreatePublicKeyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreatePublicKeyOutput {
    /// Creates a new builder-style object to manufacture [`CreatePublicKeyOutput`](crate::operation::create_public_key::CreatePublicKeyOutput).
    pub fn builder() -> crate::operation::create_public_key::builders::CreatePublicKeyOutputBuilder {
        crate::operation::create_public_key::builders::CreatePublicKeyOutputBuilder::default()
    }
}

/// A builder for [`CreatePublicKeyOutput`](crate::operation::create_public_key::CreatePublicKeyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePublicKeyOutputBuilder {
    pub(crate) public_key: ::std::option::Option<crate::types::PublicKey>,
    pub(crate) location: ::std::option::Option<::std::string::String>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreatePublicKeyOutputBuilder {
    /// <p>The public key.</p>
    pub fn public_key(mut self, input: crate::types::PublicKey) -> Self {
        self.public_key = ::std::option::Option::Some(input);
        self
    }
    /// <p>The public key.</p>
    pub fn set_public_key(mut self, input: ::std::option::Option<crate::types::PublicKey>) -> Self {
        self.public_key = input;
        self
    }
    /// <p>The public key.</p>
    pub fn get_public_key(&self) -> &::std::option::Option<crate::types::PublicKey> {
        &self.public_key
    }
    /// <p>The URL of the public key.</p>
    pub fn location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the public key.</p>
    pub fn set_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location = input;
        self
    }
    /// <p>The URL of the public key.</p>
    pub fn get_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.location
    }
    /// <p>The identifier for this version of the public key.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for this version of the public key.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The identifier for this version of the public key.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreatePublicKeyOutput`](crate::operation::create_public_key::CreatePublicKeyOutput).
    pub fn build(self) -> crate::operation::create_public_key::CreatePublicKeyOutput {
        crate::operation::create_public_key::CreatePublicKeyOutput {
            public_key: self.public_key,
            location: self.location,
            e_tag: self.e_tag,
            _request_id: self._request_id,
        }
    }
}
