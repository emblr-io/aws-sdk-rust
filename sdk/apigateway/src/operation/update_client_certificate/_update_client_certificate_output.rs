// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a client certificate used to configure client-side SSL authentication while sending requests to the integration endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateClientCertificateOutput {
    /// <p>The identifier of the client certificate.</p>
    pub client_certificate_id: ::std::option::Option<::std::string::String>,
    /// <p>The description of the client certificate.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The PEM-encoded public key of the client certificate, which can be used to configure certificate authentication in the integration endpoint .</p>
    pub pem_encoded_certificate: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp when the client certificate was created.</p>
    pub created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp when the client certificate will expire.</p>
    pub expiration_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The collection of tags. Each tag element is associated with a given resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateClientCertificateOutput {
    /// <p>The identifier of the client certificate.</p>
    pub fn client_certificate_id(&self) -> ::std::option::Option<&str> {
        self.client_certificate_id.as_deref()
    }
    /// <p>The description of the client certificate.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The PEM-encoded public key of the client certificate, which can be used to configure certificate authentication in the integration endpoint .</p>
    pub fn pem_encoded_certificate(&self) -> ::std::option::Option<&str> {
        self.pem_encoded_certificate.as_deref()
    }
    /// <p>The timestamp when the client certificate was created.</p>
    pub fn created_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_date.as_ref()
    }
    /// <p>The timestamp when the client certificate will expire.</p>
    pub fn expiration_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.expiration_date.as_ref()
    }
    /// <p>The collection of tags. Each tag element is associated with a given resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateClientCertificateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateClientCertificateOutput {
    /// Creates a new builder-style object to manufacture [`UpdateClientCertificateOutput`](crate::operation::update_client_certificate::UpdateClientCertificateOutput).
    pub fn builder() -> crate::operation::update_client_certificate::builders::UpdateClientCertificateOutputBuilder {
        crate::operation::update_client_certificate::builders::UpdateClientCertificateOutputBuilder::default()
    }
}

/// A builder for [`UpdateClientCertificateOutput`](crate::operation::update_client_certificate::UpdateClientCertificateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateClientCertificateOutputBuilder {
    pub(crate) client_certificate_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) pem_encoded_certificate: ::std::option::Option<::std::string::String>,
    pub(crate) created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) expiration_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateClientCertificateOutputBuilder {
    /// <p>The identifier of the client certificate.</p>
    pub fn client_certificate_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_certificate_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the client certificate.</p>
    pub fn set_client_certificate_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_certificate_id = input;
        self
    }
    /// <p>The identifier of the client certificate.</p>
    pub fn get_client_certificate_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_certificate_id
    }
    /// <p>The description of the client certificate.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the client certificate.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the client certificate.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The PEM-encoded public key of the client certificate, which can be used to configure certificate authentication in the integration endpoint .</p>
    pub fn pem_encoded_certificate(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pem_encoded_certificate = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The PEM-encoded public key of the client certificate, which can be used to configure certificate authentication in the integration endpoint .</p>
    pub fn set_pem_encoded_certificate(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pem_encoded_certificate = input;
        self
    }
    /// <p>The PEM-encoded public key of the client certificate, which can be used to configure certificate authentication in the integration endpoint .</p>
    pub fn get_pem_encoded_certificate(&self) -> &::std::option::Option<::std::string::String> {
        &self.pem_encoded_certificate
    }
    /// <p>The timestamp when the client certificate was created.</p>
    pub fn created_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the client certificate was created.</p>
    pub fn set_created_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_date = input;
        self
    }
    /// <p>The timestamp when the client certificate was created.</p>
    pub fn get_created_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_date
    }
    /// <p>The timestamp when the client certificate will expire.</p>
    pub fn expiration_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.expiration_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the client certificate will expire.</p>
    pub fn set_expiration_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.expiration_date = input;
        self
    }
    /// <p>The timestamp when the client certificate will expire.</p>
    pub fn get_expiration_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.expiration_date
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The collection of tags. Each tag element is associated with a given resource.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The collection of tags. Each tag element is associated with a given resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The collection of tags. Each tag element is associated with a given resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateClientCertificateOutput`](crate::operation::update_client_certificate::UpdateClientCertificateOutput).
    pub fn build(self) -> crate::operation::update_client_certificate::UpdateClientCertificateOutput {
        crate::operation::update_client_certificate::UpdateClientCertificateOutput {
            client_certificate_id: self.client_certificate_id,
            description: self.description,
            pem_encoded_certificate: self.pem_encoded_certificate,
            created_date: self.created_date,
            expiration_date: self.expiration_date,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
