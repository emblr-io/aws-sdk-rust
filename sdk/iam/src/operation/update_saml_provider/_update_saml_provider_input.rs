// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateSamlProviderInput {
    /// <p>An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your IdP.</p>
    pub saml_metadata_document: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to update.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub saml_provider_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the encryption setting for the SAML provider.</p>
    pub assertion_encryption_mode: ::std::option::Option<crate::types::AssertionEncryptionModeType>,
    /// <p>Specifies the new private key from your external identity provider. The private key must be a .pem file that uses AES-GCM or AES-CBC encryption algorithm to decrypt SAML assertions.</p>
    pub add_private_key: ::std::option::Option<::std::string::String>,
    /// <p>The Key ID of the private key to remove.</p>
    pub remove_private_key: ::std::option::Option<::std::string::String>,
}
impl UpdateSamlProviderInput {
    /// <p>An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your IdP.</p>
    pub fn saml_metadata_document(&self) -> ::std::option::Option<&str> {
        self.saml_metadata_document.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to update.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn saml_provider_arn(&self) -> ::std::option::Option<&str> {
        self.saml_provider_arn.as_deref()
    }
    /// <p>Specifies the encryption setting for the SAML provider.</p>
    pub fn assertion_encryption_mode(&self) -> ::std::option::Option<&crate::types::AssertionEncryptionModeType> {
        self.assertion_encryption_mode.as_ref()
    }
    /// <p>Specifies the new private key from your external identity provider. The private key must be a .pem file that uses AES-GCM or AES-CBC encryption algorithm to decrypt SAML assertions.</p>
    pub fn add_private_key(&self) -> ::std::option::Option<&str> {
        self.add_private_key.as_deref()
    }
    /// <p>The Key ID of the private key to remove.</p>
    pub fn remove_private_key(&self) -> ::std::option::Option<&str> {
        self.remove_private_key.as_deref()
    }
}
impl ::std::fmt::Debug for UpdateSamlProviderInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateSamlProviderInput");
        formatter.field("saml_metadata_document", &self.saml_metadata_document);
        formatter.field("saml_provider_arn", &self.saml_provider_arn);
        formatter.field("assertion_encryption_mode", &self.assertion_encryption_mode);
        formatter.field("add_private_key", &"*** Sensitive Data Redacted ***");
        formatter.field("remove_private_key", &self.remove_private_key);
        formatter.finish()
    }
}
impl UpdateSamlProviderInput {
    /// Creates a new builder-style object to manufacture [`UpdateSamlProviderInput`](crate::operation::update_saml_provider::UpdateSamlProviderInput).
    pub fn builder() -> crate::operation::update_saml_provider::builders::UpdateSamlProviderInputBuilder {
        crate::operation::update_saml_provider::builders::UpdateSamlProviderInputBuilder::default()
    }
}

/// A builder for [`UpdateSamlProviderInput`](crate::operation::update_saml_provider::UpdateSamlProviderInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateSamlProviderInputBuilder {
    pub(crate) saml_metadata_document: ::std::option::Option<::std::string::String>,
    pub(crate) saml_provider_arn: ::std::option::Option<::std::string::String>,
    pub(crate) assertion_encryption_mode: ::std::option::Option<crate::types::AssertionEncryptionModeType>,
    pub(crate) add_private_key: ::std::option::Option<::std::string::String>,
    pub(crate) remove_private_key: ::std::option::Option<::std::string::String>,
}
impl UpdateSamlProviderInputBuilder {
    /// <p>An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your IdP.</p>
    pub fn saml_metadata_document(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.saml_metadata_document = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your IdP.</p>
    pub fn set_saml_metadata_document(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.saml_metadata_document = input;
        self
    }
    /// <p>An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your IdP.</p>
    pub fn get_saml_metadata_document(&self) -> &::std::option::Option<::std::string::String> {
        &self.saml_metadata_document
    }
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to update.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    /// This field is required.
    pub fn saml_provider_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.saml_provider_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to update.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_saml_provider_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.saml_provider_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to update.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_saml_provider_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.saml_provider_arn
    }
    /// <p>Specifies the encryption setting for the SAML provider.</p>
    pub fn assertion_encryption_mode(mut self, input: crate::types::AssertionEncryptionModeType) -> Self {
        self.assertion_encryption_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the encryption setting for the SAML provider.</p>
    pub fn set_assertion_encryption_mode(mut self, input: ::std::option::Option<crate::types::AssertionEncryptionModeType>) -> Self {
        self.assertion_encryption_mode = input;
        self
    }
    /// <p>Specifies the encryption setting for the SAML provider.</p>
    pub fn get_assertion_encryption_mode(&self) -> &::std::option::Option<crate::types::AssertionEncryptionModeType> {
        &self.assertion_encryption_mode
    }
    /// <p>Specifies the new private key from your external identity provider. The private key must be a .pem file that uses AES-GCM or AES-CBC encryption algorithm to decrypt SAML assertions.</p>
    pub fn add_private_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.add_private_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the new private key from your external identity provider. The private key must be a .pem file that uses AES-GCM or AES-CBC encryption algorithm to decrypt SAML assertions.</p>
    pub fn set_add_private_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.add_private_key = input;
        self
    }
    /// <p>Specifies the new private key from your external identity provider. The private key must be a .pem file that uses AES-GCM or AES-CBC encryption algorithm to decrypt SAML assertions.</p>
    pub fn get_add_private_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.add_private_key
    }
    /// <p>The Key ID of the private key to remove.</p>
    pub fn remove_private_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.remove_private_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Key ID of the private key to remove.</p>
    pub fn set_remove_private_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.remove_private_key = input;
        self
    }
    /// <p>The Key ID of the private key to remove.</p>
    pub fn get_remove_private_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.remove_private_key
    }
    /// Consumes the builder and constructs a [`UpdateSamlProviderInput`](crate::operation::update_saml_provider::UpdateSamlProviderInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_saml_provider::UpdateSamlProviderInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_saml_provider::UpdateSamlProviderInput {
            saml_metadata_document: self.saml_metadata_document,
            saml_provider_arn: self.saml_provider_arn,
            assertion_encryption_mode: self.assertion_encryption_mode,
            add_private_key: self.add_private_key,
            remove_private_key: self.remove_private_key,
        })
    }
}
impl ::std::fmt::Debug for UpdateSamlProviderInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateSamlProviderInputBuilder");
        formatter.field("saml_metadata_document", &self.saml_metadata_document);
        formatter.field("saml_provider_arn", &self.saml_provider_arn);
        formatter.field("assertion_encryption_mode", &self.assertion_encryption_mode);
        formatter.field("add_private_key", &"*** Sensitive Data Redacted ***");
        formatter.field("remove_private_key", &self.remove_private_key);
        formatter.finish()
    }
}
